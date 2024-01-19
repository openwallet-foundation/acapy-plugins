import pytest

from marshmallow import ValidationError
from rpc.v1_0.models import RPCBaseModelSchema, RPCRequestModelSchema, RPCResponseModelSchema, RPCErrorModelSchema

rpc_base = {
  'jsonrpc': '2.0'
}

@pytest.mark.parametrize('test_input', [rpc_base])
def test_valid_rpc_base(test_input):
  schema = RPCBaseModelSchema()
  result = schema.load(test_input)

  assert result.jsonrpc == '2.0'

@pytest.mark.parametrize('test_input', [{}])
def test_invalid_rpc_base_jsonrpc_missing(test_input):
  schema = RPCBaseModelSchema()
  
  with pytest.raises(ValidationError) as exc_info:
    schema.load(test_input)

  assert 'jsonrpc' in exc_info.value.messages
  assert 'Missing data for required field.' in exc_info.value.messages['jsonrpc']

@pytest.mark.parametrize('test_input', [{
  **rpc_base,
  'method': 'test.method',
  'id': 123
}, {
  **rpc_base,
  'method': 'test.method',
  'id': '123'
}, {
  **rpc_base,
  'method': 'test.method',
  'id': None
}, {
  **rpc_base,
  'method': 'test.method'
}])
def test_valid_rpc_request(test_input):
  schema = RPCRequestModelSchema()
  result = schema.load(test_input)

  assert result.jsonrpc == '2.0'
  assert result.method == 'test.method'
  # Test optional fields
  if ('id' in test_input):
    assert result.id == test_input['id']

@pytest.mark.parametrize('test_input', [{
  **rpc_base,
  'method': 'rpc.test.method'
}])
def test_invalid_rpc_request_internal_method(test_input):
  schema = RPCRequestModelSchema()
  
  with pytest.raises(ValidationError) as exc_info:
    schema.load(test_input)
  
  assert 'method' in exc_info.value.messages
  assert 'Method name cannot be internal RPC method' in exc_info.value.messages['method']

@pytest.mark.parametrize('test_input', [{
  **rpc_base,
  'method': 'test.method',
  'id': 12.34
}])
def test_invalid_rpc_request_id_float(test_input):
  schema = RPCRequestModelSchema()
  
  with pytest.raises(ValidationError) as exc_info:
    schema.load(test_input)
  
  assert 'id' in exc_info.value.messages
  assert 'ID must be an integer, string, or null' in exc_info.value.messages['id']

@pytest.mark.parametrize('test_input', [{
  'code': -123,
  'message': 'Test error message'
}, {
  'code': 123,
  'message': 'Test error message'
}, {
  'code': '-123',
  'message': 'Test error message'
}, {
  'code': '123',
  'message': 'Test error message'
}])
def test_valid_rpc_error(test_input):
  schema = RPCErrorModelSchema()
  result = schema.load(test_input)

  assert result.code == int(test_input['code'])
  assert result.message == test_input['message']

@pytest.mark.parametrize('test_input', [{
  'message': 'Test error message'
}])
def test_invalid_rpc_error_code_missing(test_input):
  schema = RPCErrorModelSchema()

  with pytest.raises(ValidationError) as exc_info:
    schema.load(test_input)

  assert 'code' in exc_info.value.messages
  assert 'Missing data for required field.' in exc_info.value.messages['code']

@pytest.mark.parametrize('test_input', [{
  'code': 123
}])
def test_invalid_rpc_error_message_missing(test_input):
  schema = RPCErrorModelSchema()

  with pytest.raises(ValidationError) as exc_info:
    schema.load(test_input)

  assert 'message' in exc_info.value.messages
  assert 'Missing data for required field.' in exc_info.value.messages['message']

@pytest.mark.parametrize('test_input', [{
  'code': 'abc',
  'message': 'Test error message'
}])
def test_invalid_rpc_error_code_type(test_input):
  schema = RPCErrorModelSchema()

  with pytest.raises(ValidationError) as exc_info:
    schema.load(test_input)

  assert 'code' in exc_info.value.messages
  assert 'Not a valid integer.' in exc_info.value.messages['code']