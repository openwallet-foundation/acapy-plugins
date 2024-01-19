"""RPC Messages model classes and schemas."""
from typing import Any, Mapping
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import fields, validate, ValidationError

def validate_id(id):
  if not isinstance(id, (int, str, type(None))):
    raise ValidationError('ID must be an integer, string, or null')

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
  pass

class RPCErrorModel(BaseModel):
  """RPC Error Model"""

  class Meta:
    schema_class = 'RPCErrorModelSchema'
  
  def __init__(self, code, message):
    super().__init__()
    self.code = code
    self.message = message

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
                                                                 error='Method name cannot be internal RPC method'))

  # Optional parameters
  id = fields.Raw(validate=validate_id, missing=None)

class RPCResponseModelSchema(RPCBaseModelSchema):
  """Schema to allow serialization/deserialization of RPC Response Models."""
  pass

class RPCErrorModelSchema(BaseModelSchema):
  """Schema to allow serialization/deserialization of RPC Error Models."""

  class Meta:
    model_class = 'RPCErrorModel'

  code = fields.Integer(required=True)
  message = fields.String(required=True)
