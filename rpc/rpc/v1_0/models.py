"""RPC Messages model classes and schemas."""
from typing import Any, Mapping
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import fields, validate, ValidationError, validates_schema

def validate_id(id):
  if not isinstance(id, (int, str, type(None))):
    raise ValidationError('ID must be an integer, string, or null.')


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

  def __init__(self, jsonrpc, method, id):
    super().__init__(jsonrpc)
    self.method = method
    self.id = id


class RPCResponseModel(RPCBaseModel):
  """RPC Response Model"""

  def __init__(self, jsonrpc, result, error, id):
    super().__init__(jsonrpc)
    self.result = result
    self.error = error
    self.id = id

  class Meta:
    schema_class = 'RPCResponseModelSchema'


class RPCErrorModel(BaseModel):
  """RPC Error Model"""

  class Meta:
    schema_class = 'RPCErrorModelSchema'
  
  def __init__(self, code, message, data):
    super().__init__()
    self.code = code
    self.message = message
    self.data = data


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