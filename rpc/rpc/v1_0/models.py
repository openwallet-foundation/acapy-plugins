"""RPC Messages model classes and schemas."""
from typing import Any, List, Mapping, Optional, Union
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields, validate, ValidationError, validates_schema


RPC_REQUEST_EXAMPLE = {
  'jsonrpc': '2.0',
  'method': 'example.method',
  'id': 1,
  'params': ["1", "a"]
}

RPC_RESPONSE_EXAMPLE = {
  'jsonrpc': '2.0',
  'result': 'result',
  'id': 1
}


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
  
  def dump_request(self, value):
    return RPCRequestModelSchema().dump(value)
  
  def _serialize(self, value, attr, obj, **kwargs):
    if isinstance(value, list):
      return [self.dump_request(item) for item in value]
    else:
      return self.dump_request(value)

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

  def __init__(self,
               *,
               jsonrpc: str,
               **kwargs):
    super().__init__(**kwargs)
    self.jsonrpc = jsonrpc


class RPCErrorModel(BaseModel):
  """RPC Error Model"""

  class Meta:
    schema_class = 'RPCErrorModelSchema'
  
  def __init__(self,
               *,
               code,
               message,
               data,
               **kwargs):
    super().__init__(**kwargs)
    self.code = code
    self.message = message
    self.data = data


class RPCRequestModel(RPCBaseModel):
  """RPC Request Model"""

  class Meta:
    schema_class = 'RPCRequestModelSchema'

  def __init__(self,
               *,
               jsonrpc: str,
               method: str,
               id: Optional[Union[int, str]],
               params: Union[List[str], Mapping[str, str]],
               **kwargs):
    super().__init__(jsonrpc=jsonrpc, **kwargs)
    self.method = method
    self.id = id
    self.params = params


class RPCResponseModel(RPCBaseModel):
  """RPC Response Model"""

  class Meta:
    schema_class = 'RPCResponseModelSchema'

  def __init__(self,
               *,
               jsonrpc: str,
               result: Optional[Any],
               error: Optional[RPCErrorModel],
               id: Optional[Union[int, str]],
               **kwargs):
    super().__init__(jsonrpc=jsonrpc, **kwargs)
    self.result = result
    self.error = error
    self.id = id


class DRPCRecord(BaseRecord):
  """
  DIDComm RPC Record.

  Used internally to store the state of a DIDComm RPC request/response exchange.
  """

  class Meta:
    schema_class = 'DRPCRecordSchema'

  RECORD_TYPE = 'drpc_record'

  STATE_REQUEST_SENT = 'request-sent' # when request is sent
  STATE_REQUEST_RECEIVED = 'request-received' # when request is received
  STATE_COMPLETED = 'completed' # when response is sent

  def __init__(self,
               *,
               state: str,
               request: Union[RPCRequestModel, List[RPCRequestModel]],
               response: Optional[Union[RPCResponseModel, List[RPCResponseModel]]],
               **kwargs):
    super().__init__(state=state, **kwargs)
    self.request = request
    self.response = response


class RPCBaseModelSchema(BaseModelSchema):
  """Schema to allow serialization/deserialization of RPC Base Models."""

  class Meta:
    model_class = 'RPCBaseModel'

  jsonrpc = fields.String(required=True, validate=validate.Equal('2.0'))


class RPCErrorModelSchema(BaseModelSchema):
  """Schema to allow serialization/deserialization of RPC Error Models."""

  class Meta:
    model_class = 'RPCErrorModel'

  code = fields.Integer(required=True)
  message = fields.String(required=True)

  # Optional parameters
  data = fields.Raw(missing=None)


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
    
    if data.get('result') and data.get('id') is None:
      raise ValidationError('RPC response with result must have an ID.')

    if data.get('error') and data.get('id') is not None:
      raise ValidationError('RPC response with error must have a null ID.')


class DRPCRecordSchema(BaseRecordSchema):
  """Schema to allow serialization/deserialization of DIDComm RPC Request/Response Records."""

  class Meta:
    model_class = 'DRPCRecord'

  state = fields.String(required=True,
                        validate=validate.OneOf([
                          DRPCRecord.STATE_REQUEST_SENT,
                          DRPCRecord.STATE_REQUEST_RECEIVED,
                          DRPCRecord.STATE_COMPLETED
                        ]),
                        metadata={'description': 'RPC state', 'example': DRPCRecord.STATE_REQUEST_RECEIVED})

  request = Request(required=True,
                    error_messages={'null': 'RPC request cannot be empty.'},
                    metadata={'description': 'RPC request', 'example': RPC_REQUEST_EXAMPLE})

  response = Response(required=False,
                      metadata={'description': 'RPC response', 'example': RPC_RESPONSE_EXAMPLE},
                      missing=None)

  # @validates_schema
  # def validate_response_state(self, data, **kwargs):
  #   """Validate that the response is not empty if the state is in 'completed'."""

  #   if self.state != self.STATE_COMPLETED and self.response is None:
  #     raise ValidationError('RPC response cannot be empty if state is \'completed\'.')
