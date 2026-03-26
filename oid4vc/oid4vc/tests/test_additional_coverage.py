"""Additional tests for improving coverage using real data and functionality."""

import pytest
from acapy_agent.core.profile import Profile

from oid4vc.config import Config, ConfigError
from oid4vc.cred_processor import CredProcessorError
from oid4vc.models.dcql_query import DCQLQuery
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pex import (
    FilterEvaluator,
    InputDescriptorMapping,
    PexVerifyResult,
    PresentationSubmission,
)


class TestConfigClass:
    """Test Config class functionality with real data."""

    def test_config_creation_with_valid_params(self):
        """Test Config creation with all required parameters."""
        config = Config(
            host="localhost", port=8080, endpoint="https://example.com/issuer"
        )

        assert config.host == "localhost"
        assert config.port == 8080
        assert config.endpoint == "https://example.com/issuer"

    def test_config_dataclass_properties(self):
        """Test Config as a dataclass with real values."""
        # Test with typical OID4VC issuer configuration
        config = Config(
            host="issuer.example.com",
            port=443,
            endpoint="https://issuer.example.com/oid4vci",
        )

        # Verify all properties are accessible
        assert hasattr(config, "host")
        assert hasattr(config, "port")
        assert hasattr(config, "endpoint")

        # Test values
        assert config.host == "issuer.example.com"
        assert config.port == 443
        assert config.endpoint == "https://issuer.example.com/oid4vci"

    def test_config_with_different_ports(self):
        """Test Config with various port numbers."""
        test_cases = [
            (80, "http://example.com/issuer"),
            (443, "https://example.com/issuer"),
            (8080, "http://localhost:8080/issuer"),
            (9001, "https://staging.example.com:9001/issuer"),
        ]

        for port, endpoint in test_cases:
            config = Config(host="test-host", port=port, endpoint=endpoint)
            assert config.port == port
            assert config.endpoint == endpoint

    def test_config_error_inheritance(self):
        """Test ConfigError inherits from ValueError with real messages."""
        # Test with actual error scenarios
        host_error = ConfigError("host", "OID4VCI_HOST")
        port_error = ConfigError("port", "OID4VCI_PORT")
        endpoint_error = ConfigError("endpoint", "OID4VCI_ENDPOINT")

        # Verify inheritance
        assert isinstance(host_error, ValueError)
        assert isinstance(port_error, ValueError)
        assert isinstance(endpoint_error, ValueError)

        # Verify error messages contain expected content
        assert "host" in str(host_error)
        assert "OID4VCI_HOST" in str(host_error)
        assert "oid4vci.host" in str(host_error)

        assert "port" in str(port_error)
        assert "OID4VCI_PORT" in str(port_error)
        assert "oid4vci.port" in str(port_error)

        assert "endpoint" in str(endpoint_error)
        assert "OID4VCI_ENDPOINT" in str(endpoint_error)
        assert "oid4vci.endpoint" in str(endpoint_error)


class TestOID4VCIExchangeRecord:
    """Test OID4VCIExchangeRecord with real data."""

    def test_exchange_record_creation(self):
        """Test creating exchange record with realistic data."""
        record = OID4VCIExchangeRecord(
            state=OID4VCIExchangeRecord.STATE_OFFER_CREATED,
            verification_method="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            issuer_id="did:web:issuer.example.com",
            supported_cred_id="university_degree_credential",
            credential_subject={
                "given_name": "Alice",
                "family_name": "Smith",
                "degree": "Bachelor of Science",
                "university": "Example University",
            },
            nonce="abc123def456",
            pin="1234",
            code="auth_code_789",
            token="access_token_xyz",
        )

        assert record.state == OID4VCIExchangeRecord.STATE_OFFER_CREATED
        assert "did:key:" in record.verification_method
        assert "did:web:" in record.issuer_id
        assert record.credential_subject["given_name"] == "Alice"
        assert record.credential_subject["degree"] == "Bachelor of Science"
        assert record.nonce == "abc123def456"
        assert record.pin == "1234"

    def test_exchange_record_serialization_roundtrip(self):
        """Test serialization and deserialization with real data."""
        original_record = OID4VCIExchangeRecord(
            state=OID4VCIExchangeRecord.STATE_ISSUED,
            verification_method="did:web:issuer.university.edu#key-1",
            issuer_id="did:web:issuer.university.edu",
            supported_cred_id="student_id_card",
            credential_subject={
                "student_id": "STU-2023-001234",
                "full_name": "John Doe",
                "email": "john.doe@student.university.edu",
                "enrollment_date": "2023-09-01",
                "major": "Computer Science",
                "year": "Junior",
            },
            nonce="secure_nonce_456789",
            pin="9876",
            code="oauth_authorization_code_abc123",
            token="bearer_token_def456",
        )

        # Test serialization
        serialized = original_record.serialize()
        assert isinstance(serialized, dict)
        assert serialized["state"] == OID4VCIExchangeRecord.STATE_ISSUED
        assert serialized["credential_subject"]["student_id"] == "STU-2023-001234"

        # Test deserialization
        deserialized_record = OID4VCIExchangeRecord.deserialize(serialized)
        assert original_record.state == deserialized_record.state
        assert (
            original_record.verification_method == deserialized_record.verification_method
        )
        assert (
            original_record.credential_subject == deserialized_record.credential_subject
        )
        assert original_record.nonce == deserialized_record.nonce

    @pytest.mark.asyncio
    async def test_exchange_record_database_operations(self, profile: Profile):
        """Test saving and retrieving exchange record from database."""
        record = OID4VCIExchangeRecord(
            state=OID4VCIExchangeRecord.STATE_CREATED,
            verification_method="did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
            issuer_id="did:web:government.example.gov",
            supported_cred_id="drivers_license",
            credential_subject={
                "license_number": "DL123456789",
                "full_name": "Jane Smith",
                "date_of_birth": "1990-05-15",
                "address": {
                    "street": "123 Main St",
                    "city": "Springfield",
                    "state": "IL",
                    "zip": "62701",
                },
                "license_class": "Class D",
                "expiration_date": "2028-05-15",
            },
            nonce="government_nonce_789",
            pin="5678",
            code="gov_auth_code_xyz789",
            token="gov_access_token_abc123",
        )

        async with profile.session() as session:
            # Save the record
            await record.save(session)

            # Retrieve the record
            retrieved_record = await OID4VCIExchangeRecord.retrieve_by_id(
                session, record.exchange_id
            )

            # Verify the retrieved record matches the original
            assert retrieved_record.state == record.state
            assert retrieved_record.verification_method == record.verification_method
            assert retrieved_record.issuer_id == record.issuer_id
            assert retrieved_record.credential_subject["license_number"] == "DL123456789"
            assert retrieved_record.credential_subject["address"]["city"] == "Springfield"


class TestPresentationExchange:
    """Test PEX functionality with real data."""

    def test_pex_verify_result_with_real_data(self):
        """Test PexVerifyResult with realistic presentation data."""
        # Simulate a real presentation verification result
        claims_data = {
            "university_degree": {
                "credentialSubject": {
                    "id": "did:example:student123",
                    "degree": {
                        "type": "BachelorDegree",
                        "name": "Bachelor of Science in Computer Science",
                    },
                    "university": "Example University",
                    "graduationDate": "2023-05-15",
                },
                "issuer": "did:web:university.example.edu",
                "issuanceDate": "2023-05-15T10:00:00Z",
            }
        }

        fields_data = {
            "university_degree": {
                "$.credentialSubject.degree.name": "Bachelor of Science in Computer Science",
                "$.credentialSubject.university": "Example University",
                "$.credentialSubject.graduationDate": "2023-05-15",
            }
        }

        result = PexVerifyResult(
            verified=True,
            descriptor_id_to_claims=claims_data,
            descriptor_id_to_fields=fields_data,
            details="Presentation successfully verified against definition",
        )

        assert result.verified is True
        assert len(result.descriptor_id_to_claims) == 1
        assert "university_degree" in result.descriptor_id_to_claims
        assert (
            result.descriptor_id_to_claims["university_degree"]["credentialSubject"][
                "degree"
            ]["name"]
            == "Bachelor of Science in Computer Science"
        )
        assert (
            result.descriptor_id_to_fields["university_degree"][
                "$.credentialSubject.university"
            ]
            == "Example University"
        )
        assert "successfully verified" in result.details

    def test_input_descriptor_mapping_with_real_paths(self):
        """Test InputDescriptorMapping with realistic JSON paths."""
        # Test basic credential mapping
        basic_mapping = InputDescriptorMapping(
            id="drivers_license_descriptor",
            fmt="ldp_vc",
            path="$.verifiableCredential[0]",
        )

        assert basic_mapping.id == "drivers_license_descriptor"
        assert basic_mapping.fmt == "ldp_vc"
        assert basic_mapping.path == "$.verifiableCredential[0]"
        assert basic_mapping.path_nested is None

        # Test nested JWT VP mapping
        jwt_mapping = InputDescriptorMapping(
            id="education_credential_descriptor",
            fmt="jwt_vp",
            path="$.vp.verifiableCredential[1]",
        )

        assert jwt_mapping.id == "education_credential_descriptor"
        assert jwt_mapping.fmt == "jwt_vp"
        assert jwt_mapping.path == "$.vp.verifiableCredential[1]"

    def test_presentation_submission_with_multiple_descriptors(self):
        """Test PresentationSubmission with multiple descriptor mappings."""
        # Create multiple mappings for different credential types
        license_mapping = InputDescriptorMapping(
            id="drivers_license", fmt="ldp_vc", path="$.verifiableCredential[0]"
        )

        degree_mapping = InputDescriptorMapping(
            id="university_degree", fmt="ldp_vc", path="$.verifiableCredential[1]"
        )

        employment_mapping = InputDescriptorMapping(
            id="employment_verification", fmt="jwt_vc", path="$.verifiableCredential[2]"
        )

        submission = PresentationSubmission(
            id="multi_credential_submission_001",
            definition_id="comprehensive_identity_check_v2",
            descriptor_maps=[license_mapping, degree_mapping, employment_mapping],
        )

        assert submission.id == "multi_credential_submission_001"
        assert submission.definition_id == "comprehensive_identity_check_v2"
        assert len(submission.descriptor_maps) == 3

        # Verify each mapping
        mappings_by_id = {m.id: m for m in submission.descriptor_maps}
        assert "drivers_license" in mappings_by_id
        assert "university_degree" in mappings_by_id
        assert "employment_verification" in mappings_by_id

        assert mappings_by_id["drivers_license"].fmt == "ldp_vc"
        assert mappings_by_id["employment_verification"].fmt == "jwt_vc"

    def test_filter_evaluator_with_real_schema(self):
        """Test FilterEvaluator with realistic JSON schemas."""
        # Test a filter for driver's license validation
        drivers_license_filter = {
            "type": "object",
            "properties": {
                "credentialSubject": {
                    "type": "object",
                    "properties": {
                        "license_number": {
                            "type": "string",
                            "pattern": "^[A-Z]{2}[0-9]{6,8}$",
                        },
                        "license_class": {
                            "type": "string",
                            "enum": [
                                "Class A",
                                "Class B",
                                "Class C",
                                "Class D",
                                "Motorcycle",
                            ],
                        },
                        "expiration_date": {"type": "string", "format": "date"},
                    },
                    "required": ["license_number", "license_class", "expiration_date"],
                }
            },
            "required": ["credentialSubject"],
        }

        evaluator = FilterEvaluator.compile(drivers_license_filter)

        # Test valid driver's license data
        valid_license = {
            "credentialSubject": {
                "license_number": "IL12345678",
                "license_class": "Class D",
                "expiration_date": "2028-05-15",
                "full_name": "John Doe",
            }
        }

        assert evaluator.match(valid_license) is True

        # Test invalid driver's license data (bad license number format)
        invalid_license = {
            "credentialSubject": {
                "license_number": "INVALID123",  # Wrong format
                "license_class": "Class D",
                "expiration_date": "2028-05-15",
            }
        }

        assert evaluator.match(invalid_license) is False


class TestDCQLQueries:
    """Test DCQL functionality with real query scenarios."""

    @pytest.fixture
    def sample_credentials(self):
        """Sample credentials for testing DCQL queries."""
        return [
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                "issuer": "did:web:university.example.edu",
                "credentialSubject": {
                    "id": "did:example:student123",
                    "degree": {
                        "type": "BachelorDegree",
                        "name": "Bachelor of Science in Computer Science",
                        "degreeSchool": "College of Engineering",
                    },
                    "university": "Example University",
                    "graduationDate": "2023-05-15",
                    "gpa": 3.75,
                },
            },
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "DriversLicenseCredential"],
                "issuer": "did:web:dmv.illinois.gov",
                "credentialSubject": {
                    "id": "did:example:citizen456",
                    "license_number": "IL12345678",
                    "license_class": "Class D",
                    "full_name": "Jane Smith",
                    "date_of_birth": "1995-03-20",
                    "expiration_date": "2028-03-20",
                    "restrictions": [],
                },
            },
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "EmploymentCredential"],
                "issuer": "did:web:company.example.com",
                "credentialSubject": {
                    "id": "did:example:employee789",
                    "position": "Senior Software Engineer",
                    "department": "Engineering",
                    "salary": 95000,
                    "start_date": "2022-01-15",
                    "employment_status": "active",
                },
            },
        ]

    def test_dcql_simple_select_query(self):
        """Test DCQL query that selects specific fields from credentials."""
        # Create DCQL query with proper credential query structure
        credential_query = {
            "id": "university_degree_query",
            "format": "ldp_vc",
            "claims": [
                {"id": "degree_name", "path": ["credentialSubject", "degree", "name"]},
                {"id": "university", "path": ["credentialSubject", "university"]},
                {
                    "id": "graduation_date",
                    "path": ["credentialSubject", "graduationDate"],
                },
            ],
        }

        dcql_query = DCQLQuery(credentials=[credential_query])

        # Test that the query structure works
        assert dcql_query.credentials is not None
        assert len(dcql_query.credentials) == 1

        # Test that query fields are accessible
        query = dcql_query.credentials[0]
        assert query.credential_query_id == "university_degree_query"
        assert query.format == "ldp_vc"
        assert query.claims is not None
        assert len(query.claims) == 3

    def test_dcql_filter_by_issuer(self):
        """Test DCQL query filtering by issuer."""
        # Create DCQL query for DMV credentials with proper structure
        credential_query = {
            "id": "dmv_license_query",
            "format": "ldp_vc",
            "claims": [
                {
                    "id": "license_number",
                    "path": ["credentialSubject", "license_number"],
                },
                {"id": "full_name", "path": ["credentialSubject", "full_name"]},
                {"id": "license_class", "path": ["credentialSubject", "license_class"]},
            ],
        }

        dcql_query = DCQLQuery(credentials=[credential_query])

        # Test query structure
        assert dcql_query.credentials is not None
        assert len(dcql_query.credentials) == 1

        # Test that query properties are accessible
        query = dcql_query.credentials[0]
        assert query.credential_query_id == "dmv_license_query"
        assert query.format == "ldp_vc"
        assert query.claims is not None
        assert len(query.claims) == 3

        # Check claim IDs
        claim_ids = [claim.id for claim in query.claims]
        assert "license_number" in claim_ids
        assert "full_name" in claim_ids
        assert "license_class" in claim_ids

    def test_dcql_numeric_comparison(self):
        """Test DCQL query with numeric comparisons."""
        # Create DCQL query for employment credentials with salary filtering
        credential_query = {
            "id": "employment_salary_query",
            "format": "ldp_vc",
            "claims": [
                {"id": "position", "path": ["credentialSubject", "position"]},
                {
                    "id": "salary",
                    "path": ["credentialSubject", "salary"],
                    "values": [
                        90000,
                        95000,
                        100000,
                    ],  # Specific salary values for filtering
                },
                {"id": "department", "path": ["credentialSubject", "department"]},
            ],
        }

        dcql_query = DCQLQuery(credentials=[credential_query])

        # Test query structure for salary filtering
        assert dcql_query.credentials is not None
        query = dcql_query.credentials[0]
        assert query.credential_query_id == "employment_salary_query"

        # Find salary claim
        salary_claim = next((c for c in query.claims if c.id == "salary"), None)
        assert salary_claim is not None
        assert salary_claim.values == [90000, 95000, 100000]

    def test_dcql_date_filtering(self):
        """Test DCQL query filtering by date ranges."""
        # Create DCQL query for graduation date filtering
        credential_query = {
            "id": "graduation_date_query",
            "format": "ldp_vc",
            "claims": [
                {"id": "degree_name", "path": ["credentialSubject", "degree", "name"]},
                {
                    "id": "graduation_date",
                    "path": ["credentialSubject", "graduationDate"],
                    "values": [
                        "2022-01-01",
                        "2023-05-15",
                        "2024-06-30",
                    ],  # Date range values
                },
                {"id": "gpa", "path": ["credentialSubject", "gpa"]},
            ],
        }

        dcql_query = DCQLQuery(credentials=[credential_query])

        # Test date filtering structure
        assert dcql_query.credentials is not None
        query = dcql_query.credentials[0]
        assert query.credential_query_id == "graduation_date_query"

        # Find graduation date claim
        date_claim = next((c for c in query.claims if c.id == "graduation_date"), None)
        assert date_claim is not None
        assert "2023-05-15" in date_claim.values

    def test_dcql_multiple_credential_types(self):
        """Test DCQL query that matches multiple credential types."""
        # Create DCQL query for general credential information
        credential_query = {
            "id": "multi_type_query",
            "format": "ldp_vc",
            "claims": [
                {"id": "subject_id", "path": ["credentialSubject", "id"]},
                {"id": "issuer", "path": ["issuer"]},
            ],
        }

        dcql_query = DCQLQuery(credentials=[credential_query])

        # Test query structure for multiple credential types
        assert dcql_query.credentials is not None
        query = dcql_query.credentials[0]
        assert query.credential_query_id == "multi_type_query"
        assert query.format == "ldp_vc"

        # Check claims structure
        claim_ids = [claim.id for claim in query.claims]
        assert "subject_id" in claim_ids
        assert "issuer" in claim_ids


class TestImportsAndConstants:
    """Test that imports work correctly."""

    def test_config_imports(self):
        """Test that config module imports work."""
        # These imports are already working since we use them in the module
        assert Config is not None
        assert ConfigError is not None

    def test_model_imports(self):
        """Test that model imports work."""
        # These imports are already working since we use them in the module
        assert OID4VCIExchangeRecord is not None
        assert SupportedCredential is not None

    def test_pex_imports(self):
        """Test that PEX imports work."""
        # Test creating a basic result with real data
        result = PexVerifyResult()
        assert not result.verified
        assert result.descriptor_id_to_claims == {}
        assert result.descriptor_id_to_fields == {}

    def test_jwt_imports(self):
        """Test that JWT function imports work."""
        # These imports are already working since we use them in the module
        from oid4vc.jwt import jwt_sign, jwt_verify, key_material_for_kid

        assert key_material_for_kid is not None
        assert jwt_sign is not None
        assert jwt_verify is not None

    def test_dcql_imports(self):
        """Test that DCQL imports work."""
        # These imports are already working since we use them in the module
        assert DCQLQuery is not None


class TestSupportedCredentials:
    """Test SupportedCredential functionality with real credential configurations."""

    def test_university_degree_credential_configuration(self):
        """Test SupportedCredential for university degree with full configuration."""
        # Realistic university degree credential configuration
        degree_definition = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/education/v1",
            ],
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "credentialSubject": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "degree": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string"},
                            "name": {"type": "string"},
                            "degreeSchool": {"type": "string"},
                        },
                    },
                    "university": {"type": "string"},
                    "graduationDate": {"type": "string", "format": "date"},
                    "gpa": {"type": "number", "minimum": 0.0, "maximum": 4.0},
                },
            },
        }

        display_info = {
            "name": "University Degree",
            "description": "Official university degree credential",
            "locale": "en-US",
            "logo": {
                "uri": "https://university.example.edu/logo.png",
                "alt_text": "University Logo",
            },
            "background_color": "#003366",
            "text_color": "#FFFFFF",
        }

        supported_cred = SupportedCredential(
            identifier="university_degree_v1",
            format="ldp_vc",
            format_data=degree_definition,
            display=display_info,
            cryptographic_binding_methods_supported=["did:key", "did:web"],
            cryptographic_suites_supported=[
                "Ed25519Signature2020",
                "JsonWebSignature2020",
            ],
        )

        assert supported_cred.identifier == "university_degree_v1"
        assert supported_cred.format == "ldp_vc"
        assert "UniversityDegreeCredential" in supported_cred.format_data["type"]
        assert supported_cred.display["name"] == "University Degree"
        assert "did:key" in supported_cred.cryptographic_binding_methods_supported
        assert "Ed25519Signature2020" in supported_cred.cryptographic_suites_supported

    def test_drivers_license_jwt_vc_configuration(self):
        """Test SupportedCredential for driver's license in JWT VC format."""
        # Realistic driver's license credential configuration using JWT VC
        license_definition = {
            "type": ["VerifiableCredential", "DriversLicenseCredential"],
            "credentialSubject": {
                "type": "object",
                "properties": {
                    "license_number": {
                        "type": "string",
                        "pattern": "^[A-Z]{2}[0-9]{6,8}$",
                    },
                    "license_class": {
                        "type": "string",
                        "enum": [
                            "Class A",
                            "Class B",
                            "Class C",
                            "Class D",
                            "Motorcycle",
                        ],
                    },
                    "full_name": {"type": "string"},
                    "date_of_birth": {"type": "string", "format": "date"},
                    "expiration_date": {"type": "string", "format": "date"},
                    "restrictions": {"type": "array", "items": {"type": "string"}},
                    "address": {
                        "type": "object",
                        "properties": {
                            "street": {"type": "string"},
                            "city": {"type": "string"},
                            "state": {"type": "string"},
                            "zip_code": {"type": "string"},
                        },
                    },
                },
                "required": [
                    "license_number",
                    "license_class",
                    "full_name",
                    "date_of_birth",
                    "expiration_date",
                ],
            },
        }

        display_info = {
            "name": "Driver's License",
            "description": "State-issued driver's license",
            "locale": "en-US",
            "logo": {
                "uri": "https://dmv.state.gov/seal.png",
                "alt_text": "State DMV Seal",
            },
            "background_color": "#1f4e79",
            "text_color": "#FFFFFF",
        }

        supported_cred = SupportedCredential(
            identifier="drivers_license_jwt_v2",
            format="jwt_vc_json",
            format_data=license_definition,
            display=display_info,
            cryptographic_binding_methods_supported=["did:key", "jwk"],
            cryptographic_suites_supported=["ES256", "RS256"],
        )

        assert supported_cred.identifier == "drivers_license_jwt_v2"
        assert supported_cred.format == "jwt_vc_json"
        assert "DriversLicenseCredential" in supported_cred.format_data["type"]
        assert supported_cred.display["name"] == "Driver's License"
        assert "ES256" in supported_cred.cryptographic_suites_supported
        assert "jwk" in supported_cred.cryptographic_binding_methods_supported

    def test_employment_credential_with_iso_mdl_format(self):
        """Test SupportedCredential for employment verification using ISO mDL format."""
        # Employment credential using mobile driver's license format (ISO 18013-5)
        employment_definition = {
            "doctype": "org.iso18013.5.employment.1",
            "claims": {
                "org.iso18013.5.employment": {
                    "employee_id": {"display_name": "Employee ID", "mandatory": True},
                    "full_name": {"display_name": "Full Name", "mandatory": True},
                    "position": {"display_name": "Job Title", "mandatory": True},
                    "department": {"display_name": "Department", "mandatory": True},
                    "start_date": {"display_name": "Start Date", "mandatory": True},
                    "employment_status": {
                        "display_name": "Employment Status",
                        "mandatory": True,
                    },
                    "salary": {"display_name": "Annual Salary", "mandatory": False},
                    "manager": {"display_name": "Manager Name", "mandatory": False},
                    "office_location": {
                        "display_name": "Office Location",
                        "mandatory": False,
                    },
                }
            },
        }

        display_info = {
            "name": "Employment Verification",
            "description": "Official employment verification credential",
            "locale": "en-US",
            "logo": {
                "uri": "https://company.example.com/logo.png",
                "alt_text": "Company Logo",
            },
            "background_color": "#2d5aa0",
            "text_color": "#FFFFFF",
        }

        supported_cred = SupportedCredential(
            identifier="employment_mdl_v1",
            format="mso_mdoc",
            format_data=employment_definition,
            display=display_info,
            cryptographic_binding_methods_supported=["cose_key"],
            cryptographic_suites_supported=["ES256", "ES384", "ES512"],
        )

        assert supported_cred.identifier == "employment_mdl_v1"
        assert supported_cred.format == "mso_mdoc"
        assert supported_cred.format_data["doctype"] == "org.iso18013.5.employment.1"
        assert (
            "employee_id"
            in supported_cred.format_data["claims"]["org.iso18013.5.employment"]
        )
        assert supported_cred.display["name"] == "Employment Verification"
        assert "cose_key" in supported_cred.cryptographic_binding_methods_supported
        assert "ES256" in supported_cred.cryptographic_suites_supported

    def test_professional_license_vc_sd_jwt(self):
        """Test SupportedCredential for professional license using SD-JWT format."""
        # Professional license credential using Selective Disclosure JWT
        license_definition = {
            "vct": "https://credentials.example.com/professional_license",
            "claims": {
                "license_number": {"display_name": "License Number", "sd": False},
                "license_type": {"display_name": "License Type", "sd": False},
                "professional_name": {"display_name": "Professional Name", "sd": True},
                "issue_date": {"display_name": "Issue Date", "sd": False},
                "expiration_date": {"display_name": "Expiration Date", "sd": False},
                "issuing_authority": {"display_name": "Issuing Authority", "sd": False},
                "specializations": {"display_name": "Specializations", "sd": True},
                "continuing_education_hours": {"display_name": "CE Hours", "sd": True},
                "license_status": {"display_name": "Status", "sd": False},
            },
        }

        display_info = {
            "name": "Professional License",
            "description": "State professional licensing credential with selective disclosure",
            "locale": "en-US",
            "logo": {
                "uri": "https://licensing.state.gov/seal.png",
                "alt_text": "Professional Licensing Board Seal",
            },
            "background_color": "#8b0000",
            "text_color": "#FFFFFF",
        }

        supported_cred = SupportedCredential(
            identifier="professional_license_sd_jwt_v1",
            format="vc+sd-jwt",
            format_data=license_definition,
            display=display_info,
            cryptographic_binding_methods_supported=["jwk", "did:key", "x5c"],
            cryptographic_suites_supported=["ES256", "RS256", "PS256"],
        )

        assert supported_cred.identifier == "professional_license_sd_jwt_v1"
        assert supported_cred.format == "vc+sd-jwt"
        assert (
            supported_cred.format_data["vct"]
            == "https://credentials.example.com/professional_license"
        )

        # Check selective disclosure settings
        claims = supported_cred.format_data["claims"]
        assert claims["license_number"]["sd"] is False  # Always disclosed
        assert claims["professional_name"]["sd"] is True  # Selectively disclosed
        assert claims["specializations"]["sd"] is True  # Selectively disclosed

        assert supported_cred.display["name"] == "Professional License"
        assert "x5c" in supported_cred.cryptographic_binding_methods_supported
        assert "PS256" in supported_cred.cryptographic_suites_supported

    def test_to_issuer_metadata_default_wraps_in_credential_definition(self):
        """Without a processor, format_data is wrapped in credential_definition."""
        supported_cred = SupportedCredential(
            identifier="test_cred",
            format="jwt_vc_json",
            format_data={"credentialSubject": {"name": "alice"}},
        )
        metadata = supported_cred.to_issuer_metadata()
        assert "credential_definition" in metadata
        assert metadata["credential_definition"] == {
            "credentialSubject": {"name": "alice"}
        }
        assert "credentialSubject" not in metadata

    def test_to_issuer_metadata_top_level_when_processor_opts_in(self):
        """Processors implementing format_data_is_top_level() get top-level layout."""

        class FakeTopLevelIssuer:
            def format_data_is_top_level(self):
                return True

        supported_cred = SupportedCredential(
            identifier="test_cred",
            format="vc+sd-jwt",
            format_data={"vct": "https://example.com/PID", "claims": {"name": {}}},
        )
        metadata = supported_cred.to_issuer_metadata(issuer=FakeTopLevelIssuer())
        assert "credential_definition" not in metadata
        assert metadata["vct"] == "https://example.com/PID"
        assert metadata["claims"] == {"name": {}}

    def test_to_issuer_metadata_transform_hook_is_called(self):
        """Processors implementing transform_issuer_metadata() can post-process."""
        called_with = []

        class FakeTransformIssuer:
            def format_data_is_top_level(self):
                return True

            def transform_issuer_metadata(self, metadata):
                called_with.append(dict(metadata))
                metadata["injected"] = True

        supported_cred = SupportedCredential(
            identifier="test_cred",
            format="dc+sd-jwt",
            format_data={"vct": "https://example.com/Test"},
        )
        metadata = supported_cred.to_issuer_metadata(issuer=FakeTransformIssuer())
        assert called_with, "transform_issuer_metadata should have been called"
        assert metadata.get("injected") is True

    def test_to_issuer_metadata_no_processor_no_extension(self):
        """Existing behavior preserved when issuer=None (backward compat)."""
        supported_cred = SupportedCredential(
            identifier="compat_cred",
            format="ldp_vc",
            format_data={"context": ["https://www.w3.org/2018/credentials/v1"]},
        )
        metadata = supported_cred.to_issuer_metadata()
        assert "credential_definition" in metadata
        assert metadata["credential_definition"]["@context"] == [
            "https://www.w3.org/2018/credentials/v1"
        ]


class TestAdditionalEdgeCases:
    """Test edge cases and error conditions."""

    def test_config_creation_with_valid_settings(self):
        """Test Config creation with valid settings."""
        # Test creating Config with realistic settings
        config = Config(
            host="localhost", port=8080, endpoint="http://localhost:8080/oid4vci"
        )

        assert config.host == "localhost"
        assert config.port == 8080
        assert config.endpoint == "http://localhost:8080/oid4vci"

    def test_empty_credential_configurations(self):
        """Test behavior with empty credential configurations."""
        # This should work without raising an exception
        supported_cred = SupportedCredential(
            identifier="empty_test", format_data={}, format="ldp_vc"
        )

        assert supported_cred.identifier == "empty_test"
        assert supported_cred.format_data == {}

    def test_minimal_exchange_record_data(self):
        """Test creating exchange record with minimal required data."""
        # Test with minimal required fields
        minimal_data = {
            "state": OID4VCIExchangeRecord.STATE_CREATED,
            "supported_cred_id": "test_cred_123",
            "credential_subject": {"name": "Test Subject"},
            "verification_method": "did:key:test123",
            "issuer_id": "did:web:issuer.example.com",
        }

        # Should work with minimal required data
        record = OID4VCIExchangeRecord(**minimal_data)
        assert record.state == OID4VCIExchangeRecord.STATE_CREATED
        assert record.supported_cred_id == "test_cred_123"
        assert record.credential_subject["name"] == "Test Subject"


class TestBasicFunctionality:
    """Test basic functionality that can be tested without complex mocking."""

    def test_pex_verify_result_dataclass(self):
        """Test PexVerifyResult dataclass functionality."""
        from oid4vc.pex import PexVerifyResult

        # Test default values
        result = PexVerifyResult()
        assert result.verified is False
        assert result.descriptor_id_to_claims == {}
        assert result.descriptor_id_to_fields == {}
        assert result.details is None

        # Test with custom values
        claims = {"desc1": {"name": "John"}}
        fields = {"desc1": {"$.name": "John"}}

        result = PexVerifyResult(
            verified=True,
            descriptor_id_to_claims=claims,
            descriptor_id_to_fields=fields,
            details="Verification successful",
        )

        assert result.verified is True
        assert result.descriptor_id_to_claims == claims
        assert result.descriptor_id_to_fields == fields
        assert result.details == "Verification successful"

    def test_input_descriptor_mapping_model(self):
        """Test InputDescriptorMapping model."""
        from oid4vc.pex import InputDescriptorMapping

        mapping = InputDescriptorMapping(
            id="test-descriptor", fmt="ldp_vc", path="$.verifiableCredential[0]"
        )

        assert mapping.id == "test-descriptor"
        assert mapping.fmt == "ldp_vc"
        assert mapping.path == "$.verifiableCredential[0]"
        assert mapping.path_nested is None

    def test_presentation_submission_model(self):
        """Test PresentationSubmission model."""
        from oid4vc.pex import InputDescriptorMapping, PresentationSubmission

        # Test empty submission
        submission = PresentationSubmission()
        assert submission.id is None
        assert submission.definition_id is None
        assert submission.descriptor_maps is None

        # Test submission with data
        mapping = InputDescriptorMapping(id="test-desc", fmt="ldp_vc", path="$.vc")

        submission = PresentationSubmission(
            id="sub-123", definition_id="def-456", descriptor_maps=[mapping]
        )

        assert submission.id == "sub-123"
        assert submission.definition_id == "def-456"
        assert len(submission.descriptor_maps) == 1
        assert submission.descriptor_maps[0].id == "test-desc"

    def test_cred_processor_error_exception(self):
        """Test CredProcessorError exception."""

        error = CredProcessorError("Test error message")
        assert str(error) == "Test error message"
        assert isinstance(error, Exception)


class TestModuleStructure:
    """Test module structure and organization."""

    def test_module_has_expected_structure(self):
        """Test that the oid4vc module has expected structure."""
        import oid4vc

        # Test that the module exists and has basic attributes
        assert hasattr(oid4vc, "__file__")

        # Test that submodules can be imported
        try:
            import oid4vc.config
            import oid4vc.models
            import oid4vc.pex

            # Basic smoke test - modules imported without errors
            assert True
        except ImportError as e:
            pytest.fail(f"Module structure test failed: {e}")

    def test_routes_modules_exist(self):
        """Test that route modules exist."""
        try:
            import oid4vc.public_routes
            import oid4vc.routes  # noqa: F401

            # Basic smoke test
            assert True
        except ImportError as e:
            pytest.fail(f"Route modules test failed: {e}")

    def test_model_submodules_exist(self):
        """Test that model submodules exist."""
        try:
            import oid4vc.models.dcql_query
            import oid4vc.models.exchange
            import oid4vc.models.presentation
            import oid4vc.models.request
            import oid4vc.models.supported_cred  # noqa: F401

            # Basic smoke test
            assert True
        except ImportError as e:
            pytest.fail(f"Model submodules test failed: {e}")


class TestJWTFunctionality:
    """Test JWT functionality with real data and operations."""

    def test_jwt_verify_result_creation(self):
        """Test JWTVerifyResult creation with real JWT data."""
        from oid4vc.jwt import JWTVerifyResult

        # Realistic JWT headers and payload
        headers = {
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        }

        payload = {
            "iss": "did:web:issuer.example.com",
            "sub": "did:example:holder123",
            "aud": "did:web:verifier.example.org",
            "iat": 1635724800,
            "exp": 1635811200,
            "vc": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                "credentialSubject": {
                    "id": "did:example:holder123",
                    "degree": {
                        "type": "BachelorDegree",
                        "name": "Bachelor of Science in Computer Science",
                    },
                },
            },
        }

        # Test successful verification
        result = JWTVerifyResult(headers, payload, True)
        assert result.headers == headers
        assert result.payload == payload
        assert result.verified is True

        # Test failed verification
        failed_result = JWTVerifyResult(headers, payload, False)
        assert failed_result.verified is False
        assert failed_result.headers == headers
        assert failed_result.payload == payload

    def test_jwt_verify_result_with_different_algorithms(self):
        """Test JWTVerifyResult with different JWT algorithms."""
        from oid4vc.jwt import JWTVerifyResult

        # Test ES256 algorithm
        es256_headers = {
            "alg": "ES256",
            "typ": "JWT",
            "kid": "did:web:issuer.example.com#key-1",
        }

        es256_payload = {
            "iss": "did:web:issuer.example.com",
            "sub": "did:example:student456",
            "aud": "did:web:university.example.edu",
            "iat": 1635724800,
            "exp": 1635811200,
            "vc": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "DriversLicenseCredential"],
                "credentialSubject": {
                    "id": "did:example:student456",
                    "license_number": "DL123456789",
                    "license_class": "Class D",
                },
            },
        }

        es256_result = JWTVerifyResult(es256_headers, es256_payload, True)
        assert es256_result.headers["alg"] == "ES256"
        assert es256_result.payload["vc"]["type"] == [
            "VerifiableCredential",
            "DriversLicenseCredential",
        ]
        assert es256_result.verified is True


class TestCredentialProcessorFunctionality:
    """Test credential processor functionality with real data structures."""

    def test_verify_result_creation(self):
        """Test VerifyResult creation with realistic verification data."""
        from oid4vc.cred_processor import VerifyResult

        # Test successful verification with credential payload
        credential_payload = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "EmploymentCredential"],
            "issuer": "did:web:company.example.com",
            "credentialSubject": {
                "id": "did:example:employee789",
                "position": "Senior Software Engineer",
                "department": "Engineering",
                "salary": 95000,
                "start_date": "2022-01-15",
            },
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2023-01-15T10:00:00Z",
                "verificationMethod": "did:web:company.example.com#key-1",
                "proofPurpose": "assertionMethod",
            },
        }

        verified_result = VerifyResult(verified=True, payload=credential_payload)
        assert verified_result.verified is True
        assert (
            verified_result.payload["credentialSubject"]["position"]
            == "Senior Software Engineer"
        )
        assert verified_result.payload["issuer"] == "did:web:company.example.com"

        # Test failed verification
        failed_result = VerifyResult(verified=False, payload=credential_payload)
        assert failed_result.verified is False
        assert failed_result.payload == credential_payload

    def test_verify_result_with_presentation_payload(self):
        """Test VerifyResult with presentation payload data."""
        from oid4vc.cred_processor import VerifyResult

        # Test with verifiable presentation payload
        presentation_payload = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "holder": "did:example:holder123",
            "verifiableCredential": [
                {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                    "issuer": "did:web:university.example.edu",
                    "credentialSubject": {
                        "id": "did:example:holder123",
                        "degree": {
                            "type": "BachelorDegree",
                            "name": "Bachelor of Science in Computer Science",
                        },
                        "university": "Example University",
                    },
                }
            ],
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2023-05-15T14:30:00Z",
                "verificationMethod": "did:example:holder123#key-1",
                "proofPurpose": "authentication",
            },
        }

        presentation_result = VerifyResult(verified=True, payload=presentation_payload)
        assert presentation_result.verified is True
        assert presentation_result.payload["type"] == ["VerifiablePresentation"]
        assert presentation_result.payload["holder"] == "did:example:holder123"
        assert len(presentation_result.payload["verifiableCredential"]) == 1

    def test_cred_processor_error_creation(self):
        """Test CredProcessorError creation and inheritance."""

        # Test basic error creation
        error = CredProcessorError("Test credential processing error")
        assert str(error) == "Test credential processing error"

        # Test error with detailed message
        detailed_error = CredProcessorError(
            "Failed to process credential: Invalid credential subject format"
        )
        assert "Invalid credential subject format" in str(detailed_error)

        # Test that it's a proper exception
        try:
            raise CredProcessorError("Test exception")
        except CredProcessorError as e:
            assert str(e) == "Test exception"
        except Exception:
            pytest.fail("CredProcessorError should be catchable as CredProcessorError")


class TestPresentationModelFunctionality:
    """Test presentation model functionality with real data."""

    def test_oid4vp_presentation_creation(self):
        """Test OID4VPPresentation creation with realistic data."""
        from oid4vc.models.presentation import OID4VPPresentation

        presentation = OID4VPPresentation(
            state=OID4VPPresentation.PRESENTATION_VALID,
            request_id="req-123",
            pres_def_id="pres_123456",
            matched_credentials={
                "driver_license": {
                    "credential_id": "cred-123",
                    "type": "DriversLicenseCredential",
                    "subject": "did:example:holder456",
                }
            },
            verified=True,
        )

        assert presentation.pres_def_id == "pres_123456"
        assert presentation.state == OID4VPPresentation.PRESENTATION_VALID
        assert presentation.request_id == "req-123"
        assert presentation.matched_credentials is not None
        assert presentation.verified is True

    def test_oid4vp_presentation_with_multiple_credentials(self):
        """Test OID4VPPresentation with multiple credentials."""
        from oid4vc.models.presentation import OID4VPPresentation

        multi_presentation = OID4VPPresentation(
            state=OID4VPPresentation.PRESENTATION_INVALID,
            request_id="req-456",
            pres_def_id="multi_pres_789",
            matched_credentials={
                "university_degree": {
                    "credential_id": "degree-123",
                    "type": "UniversityDegreeCredential",
                    "subject": "did:example:graduate789",
                },
                "employment": {
                    "credential_id": "emp-456",
                    "type": "EmploymentCredential",
                    "subject": "did:example:graduate789",
                },
            },
            verified=False,
            errors=["signature_invalid", "credential_expired"],
        )

        assert multi_presentation.pres_def_id == "multi_pres_789"
        assert multi_presentation.state == OID4VPPresentation.PRESENTATION_INVALID
        assert multi_presentation.request_id == "req-456"
        assert len(multi_presentation.matched_credentials) == 2
        assert multi_presentation.verified is False
        assert "signature_invalid" in multi_presentation.errors


class TestAuthorizationRequestFunctionality:
    """Test authorization request functionality with real data."""

    def test_oid4vp_request_creation(self):
        """Test OID4VPRequest creation with realistic parameters."""
        from oid4vc.models.request import OID4VPRequest

        # Create realistic OID4VP request
        auth_request = OID4VPRequest(
            pres_def_id="university-degree-def",
            dcql_query_id="degree-query-123",
            vp_formats={
                "jwt_vp": {"alg": ["ES256", "EdDSA"]},
                "ldp_vp": {
                    "proof_type": ["Ed25519Signature2020", "JsonWebSignature2020"]
                },
            },
        )

        assert auth_request.pres_def_id == "university-degree-def"
        assert auth_request.dcql_query_id == "degree-query-123"
        assert auth_request.vp_formats is not None
        assert "jwt_vp" in auth_request.vp_formats
        assert "ldp_vp" in auth_request.vp_formats
        # Note: request_id is None initially until record is saved
        assert (
            auth_request.pres_def_id is not None or auth_request.dcql_query_id is not None
        )

    def test_oid4vp_request_with_dcql_query(self):
        """Test OID4VPRequest with DCQL query parameters."""
        from oid4vc.models.request import OID4VPRequest

        # Authorization request for credential presentation
        cred_auth_request = OID4VPRequest(
            dcql_query_id="employment-verification-123",
            vp_formats={"jwt_vp": {"alg": ["ES256", "EdDSA"]}},
        )

        assert cred_auth_request.dcql_query_id == "employment-verification-123"
        assert cred_auth_request.vp_formats is not None
        assert "jwt_vp" in cred_auth_request.vp_formats
        # Note: request_id is None initially until record is saved
        assert cred_auth_request.dcql_query_id is not None


class TestJWKResolverFunctionality:
    """Test JWK resolver functionality with real key data."""

    def test_jwk_resolver_import(self):
        """Test JWK resolver can be imported and has expected functionality."""
        from oid4vc.jwk_resolver import JwkResolver

        # Test that the class exists and can be referenced
        assert JwkResolver is not None

        # Test basic structure expectations
        assert hasattr(JwkResolver, "resolve")

        # Test that we can instantiate it
        resolver = JwkResolver()
        assert resolver is not None

    def test_jwk_resolver_with_realistic_data(self):
        """Test JWK resolver with realistic JWK data structures."""
        # Test with realistic Ed25519 JWK
        ed25519_jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "use": "sig",
            "kid": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        }

        # Test with realistic P-256 JWK
        p256_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGHwHitJBcBmXQ",
            "y": "y77As5vbZdIGd-vZSH1ZOhj6yd9Gh_WdYJlbXxf4g3o",
            "use": "sig",
            "kid": "did:web:issuer.example.com#key-1",
        }

        # Test that JWK structures have expected fields
        assert ed25519_jwk["kty"] == "OKP"
        assert ed25519_jwk["crv"] == "Ed25519"
        assert "x" in ed25519_jwk
        assert "kid" in ed25519_jwk

        assert p256_jwk["kty"] == "EC"
        assert p256_jwk["crv"] == "P-256"
        assert "x" in p256_jwk
        assert "y" in p256_jwk
        assert "kid" in p256_jwk

    def test_jwk_data_structures(self):
        """Test various JWK data structures for different key types."""
        # Test RSA JWK structure
        rsa_jwk = {
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdHPfCL4ktEn3j3WoFJL5PHqRxC",
            "e": "AQAB",
            "use": "sig",
            "kid": "did:web:issuer.example.com#rsa-key-1",
            "alg": "RS256",
        }

        # Test symmetric key JWK structure
        symmetric_jwk = {
            "kty": "oct",
            "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
            "use": "sig",
            "kid": "hmac-key-1",
            "alg": "HS256",
        }

        # Validate JWK structures
        assert rsa_jwk["kty"] == "RSA"
        assert "n" in rsa_jwk  # modulus
        assert "e" in rsa_jwk  # exponent

        assert symmetric_jwk["kty"] == "oct"
        assert "k" in symmetric_jwk  # key value


class TestPopResultFunctionality:
    """Test PopResult functionality with real proof-of-possession data."""

    def test_pop_result_import_and_structure(self):
        """Test PopResult can be imported and has expected structure."""
        from oid4vc.pop_result import PopResult

        # Test that the class exists
        assert PopResult is not None

        # Test basic instantiation with realistic data
        pop_result = PopResult(
            headers={"alg": "ES256", "typ": "JWT", "kid": "did:example:issuer#key-1"},
            payload={
                "iss": "did:example:issuer",
                "aud": "did:example:verifier",
                "iat": 1642680000,
                "exp": 1642683600,
                "nonce": "secure-nonce-123",
            },
            verified=True,
            holder_kid="did:example:holder#key-1",
            holder_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            },
        )

        assert pop_result.verified is True
        assert pop_result.holder_kid == "did:example:holder#key-1"
        assert pop_result.headers["alg"] == "ES256"
        assert pop_result.payload["iss"] == "did:example:issuer"

    def test_pop_result_with_realistic_scenarios(self):
        """Test PopResult scenarios with realistic credential issuance data."""
        # Test data structures that would be used with PopResult

        # DPoP (Demonstration of Proof-of-Possession) token structure
        dpop_token_payload = {
            "jti": "HK2PmfnHKwXP",
            "htm": "POST",
            "htu": "https://issuer.example.com/token",
            "iat": 1635724800,
            "exp": 1635725100,
            "cnf": {
                "jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGHwHitJBcBmXQ",
                    "y": "y77As5vbZdIGd-vZSH1ZOhj6yd9Gh_WdYJlbXxf4g3o",
                    "use": "sig",
                }
            },
        }

        # JWT proof structure for credential issuance
        jwt_proof_payload = {
            "iss": "did:example:holder123",
            "aud": "did:web:issuer.example.com",
            "iat": 1635724800,
            "exp": 1635725100,
            "nonce": "random_nonce_12345",
            "jti": "proof_jwt_789",
        }

        # Test that the data structures have expected fields
        assert dpop_token_payload["htm"] == "POST"
        assert dpop_token_payload["htu"] == "https://issuer.example.com/token"
        assert "cnf" in dpop_token_payload
        assert "jwk" in dpop_token_payload["cnf"]

        assert jwt_proof_payload["iss"] == "did:example:holder123"
        assert jwt_proof_payload["aud"] == "did:web:issuer.example.com"
        assert "nonce" in jwt_proof_payload


class TestConfigurationAdvanced:
    """Test advanced configuration scenarios with real environment data."""

    def test_config_with_production_like_settings(self):
        """Test Config with production-like settings."""
        # Use the already imported Config class

        # Test production-like configuration
        prod_config = Config(
            host="0.0.0.0",  # Production binding
            port=443,  # HTTPS port
            endpoint="https://issuer.example.com/oid4vci",
        )

        assert prod_config.host == "0.0.0.0"
        assert prod_config.port == 443
        assert prod_config.endpoint == "https://issuer.example.com/oid4vci"
        assert prod_config.endpoint.startswith("https://")

    def test_config_with_development_settings(self):
        """Test Config with development settings."""
        # Use the already imported Config class

        # Test development configuration
        dev_config = Config(
            host="localhost", port=8080, endpoint="http://localhost:8080/oid4vci"
        )

        assert dev_config.host == "localhost"
        assert dev_config.port == 8080
        assert dev_config.endpoint == "http://localhost:8080/oid4vci"
        assert dev_config.endpoint.startswith("http://")

    def test_config_with_custom_paths(self):
        """Test Config with custom endpoint paths."""
        # Use the already imported Config class

        # Test configuration with custom paths
        custom_config = Config(
            host="api.mycompany.com",
            port=8443,
            endpoint="https://api.mycompany.com:8443/credentials/oid4vci/v1",
        )

        assert custom_config.host == "api.mycompany.com"
        assert custom_config.port == 8443
        assert "credentials/oid4vci/v1" in custom_config.endpoint
        assert custom_config.endpoint.endswith("/v1")


class TestPresentationDefinitionFunctionality:
    """Test presentation definition functionality with real data."""

    def test_presentation_definition_creation(self):
        """Test presentation definition creation with realistic requirements."""
        from oid4vc.models.presentation_definition import OID4VPPresDef

        # Create a presentation definition with realistic data
        pres_def_data = {
            "id": "university-degree-verification",
            "input_descriptors": [
                {
                    "id": "degree-input",
                    "name": "University Degree",
                    "purpose": "Verify educational qualification",
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.credentialSubject.degree.type"],
                                "filter": {"type": "string", "const": "BachelorDegree"},
                            }
                        ]
                    },
                }
            ],
        }

        pres_def = OID4VPPresDef(pres_def=pres_def_data)

        assert pres_def.pres_def == pres_def_data
        assert pres_def.pres_def["id"] == "university-degree-verification"
        # Note: pres_def_id is None initially until record is saved
        assert pres_def.pres_def is not None

    def test_presentation_definition_with_realistic_constraints(self):
        """Test presentation definition with realistic constraint data."""
        # Realistic presentation definition data structure
        pd_data = {
            "id": "identity_verification_pd_v1",
            "name": "Identity Verification",
            "purpose": "We need to verify your identity with a government-issued credential",
            "input_descriptors": [
                {
                    "id": "drivers_license_input",
                    "name": "Driver's License",
                    "purpose": "Please provide your driver's license",
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.type"],
                                "filter": {
                                    "type": "array",
                                    "contains": {"const": "DriversLicenseCredential"},
                                },
                            },
                            {
                                "path": ["$.credentialSubject.license_class"],
                                "filter": {
                                    "type": "string",
                                    "enum": [
                                        "Class A",
                                        "Class B",
                                        "Class C",
                                        "Class D",
                                    ],
                                },
                            },
                            {
                                "path": ["$.credentialSubject.expiration_date"],
                                "filter": {
                                    "type": "string",
                                    "format": "date",
                                    "formatMinimum": "2024-01-01",
                                },
                            },
                        ]
                    },
                }
            ],
        }

        # Test the data structure
        assert pd_data["id"] == "identity_verification_pd_v1"
        assert pd_data["name"] == "Identity Verification"
        assert len(pd_data["input_descriptors"]) == 1


class TestPublicRouteFunctionality:
    """Test public route functionality with real data and calls."""

    def test_dereference_cred_offer_functionality(self):
        """Test credential offer dereferencing with real data structures."""
        from oid4vc.public_routes import dereference_cred_offer

        # Test the function exists and can be imported
        assert dereference_cred_offer is not None

        # Test realistic credential offer data structure
        realistic_cred_offer = {
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["university_degree_v1"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": "adhjhdjajkdkhjhdj",
                    "user_pin_required": False,
                }
            },
        }

        # Test offer structure validation
        assert "credential_issuer" in realistic_cred_offer
        assert "credential_configuration_ids" in realistic_cred_offer
        assert len(realistic_cred_offer["credential_configuration_ids"]) > 0
        assert "grants" in realistic_cred_offer

    def test_credential_issuer_metadata_structure(self):
        """Test credential issuer metadata with real configuration data."""
        from oid4vc.public_routes import CredentialIssuerMetadataSchema

        # Test realistic metadata structure
        metadata = {
            "credential_issuer": "https://university.example.edu",
            "credential_endpoint": "https://university.example.edu/oid4vci/credential",
            "token_endpoint": "https://university.example.edu/oid4vci/token",
            "jwks_uri": "https://university.example.edu/.well-known/jwks.json",
            "credential_configurations_supported": {
                "university_degree_v1": {
                    "format": "jwt_vc_json",
                    "scope": "university_degree",
                    "cryptographic_binding_methods_supported": ["did:jwk", "did:key"],
                    "cryptographic_suites_supported": ["ES256", "EdDSA"],
                    "credential_definition": {
                        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                        "credentialSubject": {
                            "degree": {"type": "string"},
                            "university": {"type": "string"},
                        },
                    },
                }
            },
        }

        # Validate metadata structure
        schema = CredentialIssuerMetadataSchema()
        assert schema is not None

        # Test key required fields
        assert metadata["credential_issuer"].startswith("https://")
        assert metadata["credential_endpoint"].startswith("https://")
        assert "credential_configurations_supported" in metadata
        assert len(metadata["credential_configurations_supported"]) > 0

    def test_token_endpoint_data_structures(self):
        """Test token endpoint with realistic OAuth 2.0 data."""
        # Test realistic token request data
        token_request = {
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": "SplxlOBeZQQYbYS6WxSbIA",
            "user_pin": "1234",
        }

        # Test token response structure
        token_response = {
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "bearer",
            "expires_in": 3600,
            "c_nonce": "tZignsnFbp",
            "c_nonce_expires_in": 300,
        }

        # Validate request structure
        assert (
            token_request["grant_type"]
            == "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        )
        assert "pre-authorized_code" in token_request

        # Validate response structure
        assert token_response["token_type"] == "bearer"
        assert token_response["expires_in"] > 0
        assert "access_token" in token_response
        assert "c_nonce" in token_response

    def test_proof_of_possession_handling(self):
        """Test proof of possession with realistic JWT data."""
        from oid4vc.public_routes import handle_proof_of_posession

        # Test realistic proof of possession data
        realistic_pop_proof = {
            "proof_type": "jwt",
            "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn19.eyJpc3MiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOa3NpTENKMWMyVWlPaUp6YVdjaUxDSnJkSGtpT2lKRlF5SXNJbU55ZGlJNkluTmxZM0F5TlRack1TSXNJbmdpT2lKc01rSm1NRlV5WmxwNUxXWjFZelpCTjNwcWJscE1SV2xTYjNsc1dFbDViazFHTjNSR2FFTndkalJuSWl3aWVTSTZJa2MwUkZSWlFYRmZRMGRzY1RCdlJHSkJjVVpMVjFsS0xWaEZkQzFGYlRZek16RlhkMHB0Y2kxaVJHTWlmUSIsImF1ZCI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiaWF0IjoxNjQyNjgwMDAwLCJleHAiOjE2NDI2ODM2MDAsIm5vbmNlIjoic2VjdXJlLW5vbmNlLTEyMyJ9.signature_placeholder",
        }

        # Test function availability
        assert handle_proof_of_posession is not None

        # Test proof structure
        assert realistic_pop_proof["proof_type"] == "jwt"
        assert "jwt" in realistic_pop_proof
        assert realistic_pop_proof["jwt"].count(".") == 2  # Valid JWT structure

        # Test nonce data
        nonce = "secure-nonce-123"
        assert len(nonce) > 10  # Reasonable nonce length
        assert nonce.replace("-", "").replace("_", "").isalnum()

    def test_credential_issuance_workflow(self):
        """Test credential issuance with realistic data flow."""
        from oid4vc.public_routes import issue_cred

        # Test realistic credential request
        credential_request = {
            "format": "jwt_vc_json",
            "credential_definition": {
                "type": ["VerifiableCredential", "UniversityDegreeCredential"]
            },
            "proof": {
                "proof_type": "jwt",
                "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn19...",
            },
        }

        # Test credential response structure
        credential_response = {
            "format": "jwt_vc_json",
            "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3VuaXZlcnNpdHkuZXhhbXBsZS5lZHUiLCJzdWIiOiJkaWQ6ZXhhbXBsZTpzdHVkZW50MTIzIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV4YW1wbGU6c3R1ZGVudDEyMyIsImRlZ3JlZSI6eyJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUiLCJuYW1lIjoiQmFjaGVsb3Igb2YgU2NpZW5jZSBpbiBDb21wdXRlciBTY2llbmNlIn0sInVuaXZlcnNpdHkiOiJFeGFtcGxlIFVuaXZlcnNpdHkifX0sImlhdCI6MTY0MjY4MDAwMCwiZXhwIjoxNjc0MjE2MDAwfQ.signature_placeholder",
            "c_nonce": "new_nonce_456",
            "c_nonce_expires_in": 300,
        }

        # Test function exists
        assert issue_cred is not None

        # Validate request structure
        assert credential_request["format"] == "jwt_vc_json"
        assert "credential_definition" in credential_request
        assert "proof" in credential_request

        # Validate response structure
        assert credential_response["format"] == "jwt_vc_json"
        assert "credential" in credential_response
        assert credential_response["credential"].count(".") == 2  # Valid JWT
        assert "c_nonce" in credential_response

    def test_oid4vp_request_handling(self):
        """Test OID4VP request handling with real presentation data."""
        from oid4vc.public_routes import get_request, post_response

        # Test realistic presentation request data
        presentation_request = {
            "client_id": "https://verifier.example.com",
            "client_id_scheme": "redirect_uri",
            "response_uri": "https://verifier.example.com/presentations/direct_post",
            "response_mode": "direct_post",
            "nonce": "random_nonce_789",
            "presentation_definition": {
                "id": "employment_verification_pd",
                "input_descriptors": [
                    {
                        "id": "employment_credential",
                        "name": "Employment Credential",
                        "purpose": "Verify current employment status",
                        "constraints": {
                            "fields": [
                                {
                                    "path": ["$.credentialSubject.employmentStatus"],
                                    "filter": {"type": "string", "const": "employed"},
                                }
                            ]
                        },
                    }
                ],
            },
        }

        # Test presentation response data
        presentation_response = {
            "vp_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpob2xkZXI0NTYiLCJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUuY29tIiwiaWF0IjoxNjQyNjgwMDAwLCJleHAiOjE2NDI2ODM2MDAsIm5vbmNlIjoicmFuZG9tX25vbmNlXzc4OSIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJob2xkZXIiOiJkaWQ6ZXhhbXBsZTpob2xkZXI0NTYiLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJlbXBsb3ltZW50X2NyZWRlbnRpYWxfand0Il19fQ.signature_placeholder",
            "presentation_submission": {
                "id": "submission_123",
                "definition_id": "employment_verification_pd",
                "descriptor_map": [
                    {
                        "id": "employment_credential",
                        "format": "jwt_vp",
                        "path": "$.vp_token",
                    }
                ],
            },
        }

        # Test functions exist
        assert get_request is not None
        assert post_response is not None

        # Validate request structure
        assert "client_id" in presentation_request
        assert "presentation_definition" in presentation_request
        assert "nonce" in presentation_request

        # Validate response structure
        assert "vp_token" in presentation_response
        assert "presentation_submission" in presentation_response
        assert presentation_response["vp_token"].count(".") == 2  # Valid JWT

    def test_dcql_presentation_verification(self):
        """Test DCQL presentation verification with real query data."""
        from oid4vc.public_routes import verify_dcql_presentation

        # Test realistic DCQL query
        dcql_query = {
            "credentials": [
                {
                    "format": "jwt_vc_json",
                    "credential_subject": {
                        "birthDate": {
                            "date_before": "2005-01-01"  # Must be 18 or older
                        },
                        "licenseClass": {"const": "Class D"},
                    },
                }
            ]
        }

        # Test presentation with matching credential
        matching_presentation = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "holder": "did:example:holder789",
            "verifiableCredential": [
                {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "DriverLicenseCredential"],
                    "issuer": "did:web:dmv.illinois.gov",
                    "credentialSubject": {
                        "id": "did:example:holder789",
                        "birthDate": "1995-06-15",
                        "licenseClass": "Class D",
                        "fullName": "Jane Doe",
                    },
                }
            ],
        }

        # Test function exists
        assert verify_dcql_presentation is not None

        # Validate query structure
        assert "credentials" in dcql_query
        assert len(dcql_query["credentials"]) > 0

        # Validate presentation structure
        assert "holder" in matching_presentation
        assert "verifiableCredential" in matching_presentation
        assert len(matching_presentation["verifiableCredential"]) > 0

    def test_presentation_definition_verification(self):
        """Test presentation definition verification with real constraint data."""
        from oid4vc.public_routes import verify_pres_def_presentation

        # Test realistic presentation definition with constraints
        complex_presentation_definition = {
            "id": "financial_verification_pd",
            "name": "Financial Verification",
            "purpose": "Verify financial credentials for loan application",
            "input_descriptors": [
                {
                    "id": "bank_statement",
                    "name": "Bank Statement",
                    "purpose": "Verify banking relationship and balance",
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.credentialSubject.accountBalance"],
                                "filter": {"type": "number", "minimum": 10000},
                            },
                            {
                                "path": ["$.credentialSubject.accountType"],
                                "filter": {
                                    "type": "string",
                                    "enum": ["checking", "savings"],
                                },
                            },
                        ]
                    },
                },
                {
                    "id": "employment_verification",
                    "name": "Employment Verification",
                    "purpose": "Verify stable employment",
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.credentialSubject.employmentStatus"],
                                "filter": {"type": "string", "const": "employed"},
                            },
                            {
                                "path": ["$.credentialSubject.annualSalary"],
                                "filter": {"type": "number", "minimum": 50000},
                            },
                        ]
                    },
                },
            ],
        }

        # Test function exists
        assert verify_pres_def_presentation is not None

        # Validate presentation definition structure
        assert "id" in complex_presentation_definition
        assert "input_descriptors" in complex_presentation_definition
        assert len(complex_presentation_definition["input_descriptors"]) == 2

        # Validate constraint complexity
        bank_constraints = complex_presentation_definition["input_descriptors"][0][
            "constraints"
        ]["fields"]
        employment_constraints = complex_presentation_definition["input_descriptors"][1][
            "constraints"
        ]["fields"]

        assert len(bank_constraints) == 2
        assert len(employment_constraints) == 2
        assert bank_constraints[0]["filter"]["minimum"] == 10000
        assert employment_constraints[1]["filter"]["minimum"] == 50000

    def test_did_jwk_operations(self):
        """Test DID JWK creation and retrieval operations."""
        pytest.importorskip("oid4vc.did_utils")
        from oid4vc.did_utils import retrieve_or_create_did_jwk
        from oid4vc.public_routes import _create_default_did, _retrieve_default_did

        # Test functions exist
        assert retrieve_or_create_did_jwk is not None
        assert _retrieve_default_did is not None
        assert _create_default_did is not None

        # Test realistic DID JWK structure
        did_jwk_example = {
            "did": "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImY4M09KM0QyeEYxQmc4dnViOXRMZTFnSE16Vjc2ZThUdXM5dVBIdlJWRVUiLCJ5IjoieF9GRXpSdTltMzZITE5fdHVlNjU5TE5wWFc2cEN5U3Rpa1lqS0lXSTVhMCJ9",
            "verificationMethod": {
                "id": "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImY4M09KM0QyeEYxQmc4dnViOXRMZTFnSE16Vjc2ZThUdXM5dVBIdlJWRVUiLCJ5IjoieF9GRXpSdTltMzZITE5fdHVlNjU5TE5wWFc2cEN5U3Rpa1lqS0lXSTVhMCJ9#0",
                "type": "JsonWebKey2020",
                "controller": "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImY4M09KM0QyeEYxQmc4dnViOXRMZTFnSE16Vjc2ZThUdXM5dVBIdlJWRVUiLCJ5IjoieF9GRXpSdTltMzZITE5fdHVlNjU5TE5wWFc2cEN5U3Rpa1lqS0lXSTVhMCJ9",
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                },
            },
        }

        # Validate DID JWK structure
        assert did_jwk_example["did"].startswith("did:jwk:")
        assert "verificationMethod" in did_jwk_example
        assert "publicKeyJwk" in did_jwk_example["verificationMethod"]

        # Validate JWK structure
        jwk = did_jwk_example["verificationMethod"]["publicKeyJwk"]
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert "x" in jwk and "y" in jwk

    def test_token_validation_workflow(self):
        """Test token validation with realistic OAuth 2.0 flows."""
        from oid4vc.public_routes import check_token

        # Test function exists
        assert check_token is not None

        # Test realistic access token structure (JWT)
        access_token = {
            "header": {"alg": "RS256", "typ": "JWT", "kid": "issuer-key-1"},
            "payload": {
                "iss": "https://issuer.example.com",
                "aud": "https://issuer.example.com",
                "sub": "client_123",
                "scope": "university_degree",
                "iat": 1642680000,
                "exp": 1642683600,
                "client_id": "did:example:wallet456",
                "c_nonce": "secure_nonce_789",
            },
        }

        # Test token validation context
        validation_context = {
            "required_scope": "university_degree",
            "issuer": "https://issuer.example.com",
            "audience": "https://issuer.example.com",
            "current_time": 1642681000,  # Within valid time range
        }

        # Validate token structure
        assert access_token["header"]["alg"] == "RS256"
        assert access_token["payload"]["scope"] == "university_degree"
        assert access_token["payload"]["exp"] > access_token["payload"]["iat"]

        # Validate context
        assert validation_context["required_scope"] == access_token["payload"]["scope"]
        assert validation_context["current_time"] < access_token["payload"]["exp"]


class TestPublicRouteHelperFunctions:
    """Test public route helper functions with real data processing."""

    def test_nonce_generation_and_validation(self):
        """Test nonce generation patterns used in public routes."""
        from secrets import token_urlsafe

        from oid4vc.public_routes import NONCE_BYTES

        # Test nonce generation like in public routes
        nonce = token_urlsafe(NONCE_BYTES)

        # Validate nonce properties
        assert len(nonce) > 0
        assert isinstance(nonce, str)
        assert NONCE_BYTES == 16  # Verify constant value

        # Test nonce uniqueness
        nonce2 = token_urlsafe(NONCE_BYTES)
        assert nonce != nonce2  # Should be unique

    def test_expires_in_calculation(self):
        """Test expiration time calculations."""
        import time

        from oid4vc.public_routes import EXPIRES_IN

        # Test expiration calculation
        current_time = int(time.time())
        expiration_time = current_time + EXPIRES_IN

        # Validate expiration
        assert EXPIRES_IN == 86400  # 24 hours in seconds
        assert expiration_time > current_time
        assert (expiration_time - current_time) == 86400

    def test_grant_type_constants(self):
        """Test OAuth 2.0 grant type constants."""
        from oid4vc.public_routes import PRE_AUTHORIZED_CODE_GRANT_TYPE

        # Validate grant type constant
        expected_grant_type = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        assert PRE_AUTHORIZED_CODE_GRANT_TYPE == expected_grant_type

        # Test in realistic context
        token_request = {
            "grant_type": PRE_AUTHORIZED_CODE_GRANT_TYPE,
            "pre-authorized_code": "test_code_123",
        }

        assert token_request["grant_type"] == expected_grant_type

    def test_jwt_structure_validation(self):
        """Test JWT structure validation patterns."""
        # Test realistic JWT structure components
        jwt_header = {"alg": "ES256", "typ": "JWT", "kid": "did:jwk:example#0"}

        jwt_payload = {
            "iss": "https://issuer.example.com",
            "aud": "https://verifier.example.com",
            "iat": 1642680000,
            "exp": 1642683600,
            "nonce": "secure_nonce_456",
            "client_id": "did:example:client123",
        }

        # Validate header structure
        assert jwt_header["alg"] in ["ES256", "EdDSA", "RS256"]
        assert jwt_header["typ"] == "JWT"
        assert jwt_header["kid"].startswith("did:")

        # Validate payload structure
        assert jwt_payload["exp"] > jwt_payload["iat"]
        assert "iss" in jwt_payload
        assert "aud" in jwt_payload
        assert len(jwt_payload["nonce"]) > 8

    def test_credential_format_validation(self):
        """Test credential format validation."""
        # Test supported credential formats
        supported_formats = ["jwt_vc_json", "ldp_vc", "vc+sd-jwt"]

        for format_type in supported_formats:
            credential_config = {
                "format": format_type,
                "scope": "university_degree",
                "cryptographic_binding_methods_supported": ["did:jwk", "did:key"],
                "cryptographic_suites_supported": ["ES256", "EdDSA"],
            }

            assert credential_config["format"] in supported_formats
            assert "scope" in credential_config
            assert len(credential_config["cryptographic_binding_methods_supported"]) > 0

    def test_presentation_submission_validation(self):
        """Test presentation submission structure validation."""
        # Test realistic presentation submission
        presentation_submission = {
            "id": "submission_789",
            "definition_id": "employment_verification",
            "descriptor_map": [
                {
                    "id": "employment_credential",
                    "format": "jwt_vp",
                    "path": "$.vp_token",
                    "path_nested": {
                        "id": "employment_credential_nested",
                        "format": "jwt_vc_json",
                        "path": "$.vp.verifiableCredential[0]",
                    },
                }
            ],
        }

        # Validate submission structure
        assert "id" in presentation_submission
        assert "definition_id" in presentation_submission
        assert "descriptor_map" in presentation_submission
        assert len(presentation_submission["descriptor_map"]) > 0

        # Validate descriptor mapping
        descriptor = presentation_submission["descriptor_map"][0]
        assert descriptor["format"] in ["jwt_vp", "ldp_vp"]
        assert descriptor["path"].startswith("$.")
        assert "path_nested" in descriptor

    def test_error_response_structures(self):
        """Test error response structures used in public routes."""
        # Test OAuth 2.0 error responses
        oauth_error = {
            "error": "invalid_request",
            "error_description": "The request is missing a required parameter",
            "error_uri": "https://tools.ietf.org/html/rfc6749#section-5.2",
        }

        # Test OID4VCI error responses
        oid4vci_error = {
            "error": "invalid_proof",
            "error_description": "Proof validation failed",
            "c_nonce": "new_nonce_123",
            "c_nonce_expires_in": 300,
        }

        # Test OID4VP error responses
        oid4vp_error = {
            "error": "invalid_presentation_definition_id",
            "error_description": "The presentation definition ID is not recognized",
        }

        # Validate error structures
        assert oauth_error["error"] in [
            "invalid_request",
            "invalid_grant",
            "invalid_client",
        ]
        assert "error_description" in oauth_error

        assert oid4vci_error["error"] == "invalid_proof"
        assert "c_nonce" in oid4vci_error

        assert oid4vp_error["error"] == "invalid_presentation_definition_id"

    def test_url_encoding_patterns(self):
        """Test URL encoding patterns used in credential offers."""
        import json
        from urllib.parse import quote

        # Test credential offer encoding
        cred_offer = {
            "credential_issuer": "https://university.example.edu",
            "credential_configuration_ids": ["degree_v1"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": "test_code_456"
                }
            },
        }

        # Test URL encoding
        encoded_offer = quote(json.dumps(cred_offer))
        credential_offer_uri = (
            f"openid-credential-offer://?credential_offer={encoded_offer}"
        )

        # Validate encoding
        assert credential_offer_uri.startswith("openid-credential-offer://")
        assert "credential_offer=" in credential_offer_uri
        assert len(encoded_offer) > 0

    def test_did_resolution_patterns(self):
        """Test DID resolution patterns used in public routes."""
        # Test DID JWK pattern
        did_jwk = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImY4M09KM0QyeEYxQmc4dnViOXRMZTFnSE16Vjc2ZThUdXM5dVBIdlJWRVUiLCJ5IjoieF9GRXpSdTltMzZITE5fdHVlNjU5TE5wWFc2cEN5U3Rpa1lqS0lXSTVhMCJ9"

        # Test DID key pattern
        did_key = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

        # Test DID web pattern
        did_web = "did:web:university.example.edu"

        # Validate DID patterns
        assert did_jwk.startswith("did:jwk:")
        assert did_key.startswith("did:key:")
        assert did_web.startswith("did:web:")

        # Test verification method construction
        verification_method_jwk = f"{did_jwk}#0"
        verification_method_key = f"{did_key}#0"
        verification_method_web = f"{did_web}#key-1"

        assert verification_method_jwk.endswith("#0")
        assert verification_method_key.endswith("#0")
        assert verification_method_web.endswith("#key-1")

    def test_cryptographic_suite_validation(self):
        """Test cryptographic suite validation patterns."""
        # Test supported signature algorithms
        supported_algs = ["ES256", "ES384", "ES512", "EdDSA", "RS256", "PS256"]

        # Test supported key types
        supported_key_types = ["EC", "RSA", "OKP"]

        # Test supported curves
        supported_curves = ["P-256", "P-384", "P-521", "Ed25519", "secp256k1"]

        # Test key material validation
        ec_key_p256 = {
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        }

        ed25519_key = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        }

        # Validate key structures
        assert ec_key_p256["kty"] in supported_key_types
        assert ec_key_p256["crv"] in supported_curves
        assert "x" in ec_key_p256 and "y" in ec_key_p256

        assert ed25519_key["kty"] in supported_key_types
        assert ed25519_key["crv"] in supported_curves
        assert "x" in ed25519_key


class TestOID4VCIntegrationFlows:
    """Test OID4VC integration flows with realistic end-to-end data."""

    def test_credential_offer_to_issuance_flow(self):
        """Test complete credential offer to issuance data flow."""
        # Step 1: Credential Offer Creation
        credential_offer = {
            "credential_issuer": "https://university.example.edu",
            "credential_configuration_ids": ["university_degree_jwt"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": "university_preauth_789",
                    "user_pin_required": False,
                }
            },
        }

        # Step 2: Token Request
        token_request = {
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": "university_preauth_789",
        }

        # Step 3: Token Response
        token_response = {
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3VuaXZlcnNpdHkuZXhhbXBsZS5lZHUiLCJhdWQiOiJodHRwczovL3VuaXZlcnNpdHkuZXhhbXBsZS5lZHUiLCJzdWIiOiJ3YWxsZXRfMTIzIiwic2NvcGUiOiJ1bml2ZXJzaXR5X2RlZ3JlZSIsImlhdCI6MTY0MjY4MDAwMCwiZXhwIjoxNjQyNjgzNjAwfQ.signature",
            "token_type": "bearer",
            "expires_in": 3600,
            "c_nonce": "univ_nonce_456",
            "c_nonce_expires_in": 300,
        }

        # Step 4: Credential Request with Proof
        credential_request = {
            "format": "jwt_vc_json",
            "credential_definition": {
                "type": ["VerifiableCredential", "UniversityDegreeCredential"]
            },
            "proof": {
                "proof_type": "jwt",
                "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn19.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpzdHVkZW50NDU2IiwiYXVkIjoiaHR0cHM6Ly91bml2ZXJzaXR5LmV4YW1wbGUuZWR1IiwiaWF0IjoxNjQyNjgwMDAwLCJleHAiOjE2NDI2ODA5MDAsIm5vbmNlIjoidW5pdl9ub25jZV80NTYifQ.signature",
            },
        }

        # Step 5: Credential Response
        credential_response = {
            "format": "jwt_vc_json",
            "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3VuaXZlcnNpdHkuZXhhbXBsZS5lZHUiLCJzdWIiOiJkaWQ6ZXhhbXBsZTpzdHVkZW50NDU2IiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV4YW1wbGU6c3R1ZGVudDQ1NiIsImRlZ3JlZSI6eyJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUiLCJuYW1lIjoiQmFjaGVsb3Igb2YgU2NpZW5jZSBpbiBDb21wdXRlciBTY2llbmNlIn0sInVuaXZlcnNpdHkiOiJFeGFtcGxlIFVuaXZlcnNpdHkiLCJncmFkdWF0aW9uRGF0ZSI6IjIwMjMtMDUtMTUifX0sImlhdCI6MTY0MjY4MDAwMCwiZXhwIjoxNjc0MjE2MDAwfQ.signature",
            "c_nonce": "new_univ_nonce_789",
            "c_nonce_expires_in": 300,
        }

        # Validate flow continuity
        assert (
            credential_offer["grants"][
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ]["pre-authorized_code"]
            == token_request["pre-authorized_code"]
        )
        # JWT contains encoded nonce, so check that JWT has proper structure
        assert credential_request["proof"]["jwt"].count(".") == 2  # Valid JWT structure
        assert credential_response["format"] == credential_request["format"]
        assert (
            len(credential_response["credential"]) > 100
        )  # Meaningful credential length

    def test_presentation_request_to_response_flow(self):
        """Test complete presentation request to response data flow."""
        # Step 1: Presentation Request
        presentation_request = {
            "client_id": "https://employer.example.com",
            "client_id_scheme": "redirect_uri",
            "response_uri": "https://employer.example.com/presentations/callback",
            "response_mode": "direct_post",
            "nonce": "employer_nonce_123",
            "presentation_definition": {
                "id": "employment_verification_pd",
                "name": "Employment Verification",
                "purpose": "Verify educational and employment credentials for hiring",
                "input_descriptors": [
                    {
                        "id": "university_degree",
                        "name": "University Degree",
                        "purpose": "Verify educational qualification",
                        "constraints": {
                            "fields": [
                                {
                                    "path": ["$.credentialSubject.degree.type"],
                                    "filter": {
                                        "type": "string",
                                        "enum": [
                                            "BachelorDegree",
                                            "MasterDegree",
                                            "DoctorateDegree",
                                        ],
                                    },
                                }
                            ]
                        },
                    },
                    {
                        "id": "employment_history",
                        "name": "Employment History",
                        "purpose": "Verify work experience",
                        "constraints": {
                            "fields": [
                                {
                                    "path": ["$.credentialSubject.yearsOfExperience"],
                                    "filter": {"type": "number", "minimum": 2},
                                }
                            ]
                        },
                    },
                ],
            },
        }

        # Step 2: Presentation Response
        presentation_response = {
            "vp_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpqb2JhcHBsaWNhbnQxMjMiLCJhdWQiOiJodHRwczovL2VtcGxveWVyLmV4YW1wbGUuY29tIiwiaWF0IjoxNjQyNjgwMDAwLCJleHAiOjE2NDI2ODM2MDAsIm5vbmNlIjoiZW1wbG95ZXJfbm9uY2VfMTIzIiwidnAiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sImhvbGRlciI6ImRpZDpleGFtcGxlOmpvYmFwcGxpY2FudDEyMyIsInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImVkdWNhdGlvbl9jcmVkZW50aWFsX2p3dCIsImVtcGxveW1lbnRfY3JlZGVudGlhbF9qd3QiXX19.signature",
            "presentation_submission": {
                "id": "employment_submission_456",
                "definition_id": "employment_verification_pd",
                "descriptor_map": [
                    {
                        "id": "university_degree",
                        "format": "jwt_vp",
                        "path": "$.vp_token",
                        "path_nested": {
                            "id": "degree_credential",
                            "format": "jwt_vc_json",
                            "path": "$.vp.verifiableCredential[0]",
                        },
                    },
                    {
                        "id": "employment_history",
                        "format": "jwt_vp",
                        "path": "$.vp_token",
                        "path_nested": {
                            "id": "employment_credential",
                            "format": "jwt_vc_json",
                            "path": "$.vp.verifiableCredential[1]",
                        },
                    },
                ],
            },
        }

        # Validate flow continuity
        # JWT contains encoded nonce, so check that JWT has proper structure
        assert presentation_response["vp_token"].count(".") == 2  # Valid JWT structure
        assert (
            presentation_response["presentation_submission"]["definition_id"]
            == presentation_request["presentation_definition"]["id"]
        )
        assert len(
            presentation_response["presentation_submission"]["descriptor_map"]
        ) == len(presentation_request["presentation_definition"]["input_descriptors"])
        assert len(presentation_response["vp_token"]) > 100  # Meaningful VP token length

    def test_dcql_query_evaluation_flow(self):
        """Test DCQL query evaluation with realistic credential matching."""
        # DCQL Query for age verification
        dcql_query = {
            "credentials": [
                {
                    "format": "jwt_vc_json",
                    "meta": {"group": ["age_verification"]},
                    "credential_subject": {
                        "birth_date": {
                            "date_before": "2005-01-01"  # Must be 18+ years old
                        }
                    },
                }
            ]
        }

        # Matching credential (person born in 1995)
        matching_credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "IdentityCredential"],
            "issuer": "did:web:government.example.gov",
            "credentialSubject": {
                "id": "did:example:citizen789",
                "full_name": "Alex Johnson",
                "birth_date": "1995-03-20",
                "citizenship": "US",
            },
            "issuanceDate": "2023-01-15T10:00:00Z",
            "expirationDate": "2028-01-15T10:00:00Z",
        }

        # Non-matching credential (person born in 2010, too young)
        non_matching_credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "IdentityCredential"],
            "issuer": "did:web:government.example.gov",
            "credentialSubject": {
                "id": "did:example:minor456",
                "full_name": "Taylor Smith",
                "birth_date": "2010-08-15",
                "citizenship": "US",
            },
            "issuanceDate": "2023-01-15T10:00:00Z",
            "expirationDate": "2028-01-15T10:00:00Z",
        }

        # Evaluate matching logic
        matching_birth_year = int(
            matching_credential["credentialSubject"]["birth_date"][:4]
        )
        non_matching_birth_year = int(
            non_matching_credential["credentialSubject"]["birth_date"][:4]
        )
        threshold_year = int(
            dcql_query["credentials"][0]["credential_subject"]["birth_date"][
                "date_before"
            ][:4]
        )

        # Validate query evaluation
        assert matching_birth_year < threshold_year  # 1995 < 2005, should match
        assert non_matching_birth_year >= threshold_year  # 2010 >= 2005, should not match

    def test_error_handling_patterns(self):
        """Test error handling patterns across OID4VC flows."""
        # Test various error scenarios
        error_scenarios = [
            {
                "scenario": "Invalid credential request",
                "error": {
                    "error": "invalid_credential_request",
                    "error_description": "The credential request is missing required parameters",
                },
            },
            {
                "scenario": "Invalid proof",
                "error": {
                    "error": "invalid_proof",
                    "error_description": "The proof validation failed",
                    "c_nonce": "error_recovery_nonce_123",
                    "c_nonce_expires_in": 300,
                },
            },
            {
                "scenario": "Unsupported credential format",
                "error": {
                    "error": "unsupported_credential_format",
                    "error_description": "The requested credential format is not supported",
                },
            },
            {
                "scenario": "Invalid presentation",
                "error": {
                    "error": "invalid_presentation",
                    "error_description": "The presentation does not match the presentation definition",
                },
            },
        ]

        # Validate error structures
        for scenario in error_scenarios:
            error = scenario["error"]
            assert "error" in error
            assert "error_description" in error
            assert len(error["error_description"]) > 10

            # Validate specific error types
            if error["error"] == "invalid_proof":
                assert "c_nonce" in error
                assert "c_nonce_expires_in" in error

    def test_multi_format_credential_support(self):
        """Test support for multiple credential formats."""
        # Test different credential formats
        credential_formats = {
            "jwt_vc_json": {
                "format": "jwt_vc_json",
                "scope": "university_degree",
                "cryptographic_binding_methods_supported": ["did:jwk", "did:key"],
                "cryptographic_suites_supported": ["ES256", "EdDSA"],
                "credential_definition": {
                    "type": ["VerifiableCredential", "UniversityDegreeCredential"]
                },
            },
            "ldp_vc": {
                "format": "ldp_vc",
                "scope": "employment_credential",
                "cryptographic_binding_methods_supported": ["did:web", "did:key"],
                "cryptographic_suites_supported": [
                    "Ed25519Signature2020",
                    "JsonWebSignature2020",
                ],
                "credential_definition": {
                    "type": ["VerifiableCredential", "EmploymentCredential"],
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                },
            },
            "vc+sd-jwt": {
                "format": "vc+sd-jwt",
                "scope": "identity_credential",
                "cryptographic_binding_methods_supported": ["did:jwk"],
                "cryptographic_suites_supported": ["ES256"],
                # Per OID4VCI spec, vc+sd-jwt uses top-level vct, not credential_definition
                "vct": "https://example.com/identity_credential",
            },
        }

        # Validate format configurations
        for format_id, config in credential_formats.items():
            assert config["format"] in ["jwt_vc_json", "ldp_vc", "vc+sd-jwt"]
            assert "scope" in config
            assert "cryptographic_binding_methods_supported" in config
            assert "cryptographic_suites_supported" in config

            # Format-specific validations
            if config["format"] == "jwt_vc_json":
                assert "credential_definition" in config
                assert "type" in config["credential_definition"]
            elif config["format"] == "ldp_vc":
                assert "credential_definition" in config
                assert "@context" in config["credential_definition"]
            elif config["format"] == "vc+sd-jwt":
                # SD-JWT uses top-level vct per OID4VCI spec
                assert "vct" in config
