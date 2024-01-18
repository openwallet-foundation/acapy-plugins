"""RPC Messages model classes and schemas."""
from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema

class RPCRequestRecord(BaseRecord):
  """RPC Request Record"""
  pass

class RPCResponseRecord(BaseRecord):
  """RPC Response Record"""
  pass

class RPCErrorRecord(BaseRecord):
  """RPC Error Record"""
  pass

class RPCRequestRecordSchema(BaseRecordSchema):
  """Schema to allow serialization/deserialization of RPC Request Records."""
  pass

class RPCResponseRecordSchema(BaseRecordSchema):
  """Schema to allow serialization/deserialization of RPC Response Records."""
  pass

class RPCErrorRecordSchema(BaseRecordSchema):
  """Schema to allow serialization/deserialization of RPC Error Records."""
  pass