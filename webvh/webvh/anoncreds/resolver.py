import requests


class DIDWebVHResolver:
    
    def __init__(self):
        pass
    
    def validate_did_uri(self, resource_id: str):
        assert resource_id.split(':')[0] == 'did'
        assert resource_id.split(':')[1] == 'webvh'
        assert resource_id.split(':')[2]
        assert resource_id.split(':')[3]
    
    def id_to_did_doc_uri(self, resource_id: str):
        domain = resource_id.split(':')[3]
        path = '/'.join(resource_id.split('/')[-1].split(':')[4:])
        if path:
            domain += path
        else:
            domain += '/.well-known'
        return f'https://{domain}/did.json'
    
    def id_to_url(self, resource_id: str):
        domain = resource_id.split(':')[3]
        path = '/'.join(resource_id.split(':')[4:])
        return f'https://{domain}/{path}'
    
    def resolve_resource(self, resource_id: str):
        # did_url = self.id_to_did_doc_uri(resource_id)
        resource_url = self.id_to_url(resource_id)
        r = requests.get(resource_url)
        resource = r.json()

        assert resource.get('@context')
        assert resource.get('type')
        assert resource.get('id')
        assert resource.get('resourceContent')
        assert resource.get('resourceMetadata')
        assert resource.get('proof')
        
        attested_resource = resource
        
        proof = resource.pop('proof')
        proof = proof if isinstance(proof, dict) else proof[0]
        # verify(resource, proof)
        
        resource_digest = attested_resource.get('resourceMetadata').get('resourceId')
        assert resource_digest == resource_url.split('/')[-1].split('.')[0]
        
        return attested_resource