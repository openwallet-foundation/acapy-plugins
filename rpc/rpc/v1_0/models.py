"""RPC Messages model classes and schemas."""
from typing import List, Mapping, Union
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields, validate, ValidationError, validates_schema

def validate_id(id):
  if not isinstance(id, (int, str, type(None))):
    raise ValidationError('ID must be an integer, string, or null.')
  

class Params(fields.Field):
  """RPC Params field. Can be either a list of strings or a key value mapping of strings."""

  def _deserialize(self, value, attr, data, **kwargs):
    if isinstance(value, list):
      return value
    elif isinstance(value, Mapping):
      return value
    else:
      raise ValidationError('Params must be an array, object, or null.')


class Request(fields.Field):
  """RPC Request field. Can be either a single RPCRequest or a list of RPCRequest."""

  def load_request(self, value):
    return RPCRequestModelSchema().load(value)

  def _deserialize(self, value, attr, data, **kwargs):
    if isinstance(value, list):
      if not len(value):
        raise ValidationError('RPC request cannot be empty.')
      # Map through list and load each item
      return [self.load_request(item) for item in value]
    else:
      if not value:
        raise ValidationError('RPC request cannot be empty.')
      return self.load_request(value)


class Response(fields.Field):
  """RPC Response field. Can be either a single RPCResponse, a single RPCError or a list of RPCResponses or RPCErrors."""

  def load_response_or_error(self, value):
      return RPCResponseModelSchema().load(value)

  def _deserialize(self, value, attr, data, **kwargs):
    if isinstance(value, list):
      if not len(value):
        raise ValidationError('RPC response cannot be empty.')
      # Map through list and load each item
      return [self.load_response_or_error(item) for item in value]
    else:
      if not value:
        raise ValidationError('RPC response cannot be empty.')
      return self.load_response_or_error(value)


class RPCBaseModel(BaseModel):
  """RPC Base Model"""

  class Meta:
    schema_class = 'RPCBaseModelSchema'

  def __init__(self, jsonrpc):
    super().__init__()
    self.jsonrpc = jsonrpc


class RPCRequestModel(RPCBaseModel):
  """RPC Request Model"""

  class Meta:
    schema_class = 'RPCRequestModelSchema'

  def __init__(self, jsonrpc, method, id, params):
    super().__init__(jsonrpc)
    self.method = method
    self.id = id
    self.params = params


class RPCResponseModel(RPCBaseModel):
  """RPC Response Model"""

  class Meta:
    schema_class = 'RPCResponseModelSchema'

  def __init__(self, jsonrpc, result, error, id):
    super().__init__(jsonrpc)
    self.result = result
    self.error = error
    self.id = id


class RPCErrorModel(BaseModel):
  """RPC Error Model"""

  class Meta:
    schema_class = 'RPCErrorModelSchema'
  
  def __init__(self, code, message, data):
    super().__init__()
    self.code = code
    self.message = message
    self.data = data


class DRPCRequestRecord(BaseRecord):
  """DIDComm RPC Request Record"""

  class Meta:
    schema_class = 'DRPCequestRecordSchema'

  # TODO: Add correct type
  RECORD_TYPE = 'drpc_request_record'

  STATE_REQUEST_SENT = 'request-sent' # when request is sent
  STATE_COMPLETED = 'completed' # when response is received

  def __init__(self, *,
               state = STATE_REQUEST_SENT, request: Union[RPCRequestModel, List[RPCRequestModel]],
               **kwargs):
    super().__init__(state=state, **kwargs)
    self.request = request


class DRPCResponseRecord(BaseRecord):
  """DIDComm RPC Response Record"""

  class Meta:
    schema_class = 'DRPCResponseRecordSchema'

  # TODO: Add correct type
  RECORD_TYPE = 'drpc_response_record'

  STATE_REQUEST_RECEIVED = 'request-received' # when request is received
  STATE_COMPLETED = 'completed' # when response is sent

  def __init__(self, *,
               state = STATE_REQUEST_RECEIVED,
               response: Union[RPCResponseModel, RPCErrorModel, List[Union[RPCResponseModel, RPCErrorModel]]],
               **kwargs):
    super().__init__(state=state, **kwargs)
    self.response = response


class RPCBaseModelSchema(BaseModelSchema):
  """Schema to allow serialization/deserialization of RPC Base Models."""

  class Meta:
    model_class = 'RPCBaseModel'

  jsonrpc = fields.String(required=True, validate=validate.Equal('2.0'))


class RPCRequestModelSchema(RPCBaseModelSchema):
  """Schema to allow serialization/deserialization of RPC Request Models."""

  class Meta:
    model_class = 'RPCRequestModel'

  method = fields.String(required=True, validate=validate.Regexp(regex='^(?!rpc\.).*$',
                                                                 error='Method name cannot be internal RPC method.'))

  # Optional parameters
  id = fields.Raw(validate=validate_id, missing=None)
  params = Params(missing=None)


class RPCResponseModelSchema(RPCBaseModelSchema):
  """Schema to allow serialization/deserialization of RPC Response Models."""

  class Meta:
    model_class = 'RPCResponseModel'

  result = fields.Raw(missing=None)
  error = fields.Nested('RPCErrorModelSchema', missing=None)
  id = fields.Raw(required=True, validate=validate_id, allow_none=True)

  @validates_schema
  def validate_response(self, data, **kwargs):
    """Validate that RPC response has either a result or an error but not both."""

    if not data.get('result') and not data.get('error'):
      raise ValidationError('RPC response must have either result or error.')
    
    if data.get('result') and data.get('error'):
      raise ValidationError('RPC response cannot have both result and error.')
    

class RPCErrorModelSchema(BaseModelSchema):
  """Schema to allow serialization/deserialization of RPC Error Models."""

  class Meta:
    model_class = 'RPCErrorModel'

  code = fields.Integer(required=True)
  message = fields.String(required=True)

  # Optional parameters
  data = fields.Raw(missing=None)


class DRPCRequestRecordSchema(BaseRecordSchema):
  """Schema to allow serialization/deserialization of DPRC Request Records."""

  class Meta:
    model_class = 'DRPCRequestRecord'

  request = Request(required=True, error_messages={'null': 'RPC request cannot be empty.'})


class DRPCResponseRecordSchema(BaseRecordSchema):
  """Schema to allow serialization/deserialization of DPRC Response Records."""

  class Meta:
    model_class = 'DRPCResponseRecord'

  response = Response(required=True, error_messages={'null': 'RPC response cannot be empty.'})
