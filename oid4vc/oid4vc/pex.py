"""Presentation Exchange evaluation."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

import jsonpath_ng as jsonpath
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModel, BaseModelSchema
from acapy_agent.messaging.valid import UUID4_EXAMPLE
from acapy_agent.protocols.present_proof.dif.pres_exch import (
    DIFField,
    InputDescriptors,
    PresentationDefinition,
)
from acapy_agent.protocols.present_proof.dif.pres_exch import (
    InputDescriptorMapping as InnerInDescMapping,
)
from acapy_agent.protocols.present_proof.dif.pres_exch import (
    InputDescriptorMappingSchema as InnerInDescMappingSchema,
)
from jsonpath_ng import DatumInContext as Matched
from jsonpath_ng import JSONPath
from jsonschema import Draft7Validator, ValidationError
from marshmallow import EXCLUDE, fields

from oid4vc.cred_processor import CredProcessors


# TODO Update ACA-Py's InputDescriptorMapping model to match this
class InputDescriptorMapping(BaseModel):
    """Single InputDescriptorMapping object."""

    class Meta:
        """InputDescriptorMapping metadata."""

        schema_class = "InputDescriptorMappingSchema"

    def __init__(
        self,
        *,
        id: str,
        fmt: str,
        path: str,
        path_nested: Optional[InnerInDescMapping] = None,
    ):
        """Initialize InputDescriptorMapping."""
        self.id = id
        self.fmt = fmt
        self.path = path
        self.path_nested = path_nested


class InputDescriptorMappingSchema(BaseModelSchema):
    """Single InputDescriptorMapping Schema."""

    class Meta:
        """InputDescriptorMappingSchema metadata."""

        model_class = InputDescriptorMapping
        unknown = EXCLUDE

    id = fields.Str(required=True, metadata={"description": "ID"})
    fmt = fields.Str(
        required=True,
        dump_default="ldp_vc",
        data_key="format",
        metadata={"description": "Format"},
    )
    path = fields.Str(required=True, metadata={"description": "Path"})
    path_nested = fields.Nested(
        InnerInDescMappingSchema(),
        required=False,
        metadata={"description": "Path nested"},
    )


# TODO Update ACA-Py's Pres Submission model to match this
class PresentationSubmission(BaseModel):
    """Single PresentationSubmission object."""

    class Meta:
        """PresentationSubmission metadata."""

        schema_class = "PresentationSubmissionSchema"

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        definition_id: Optional[str] = None,
        descriptor_maps: Optional[Sequence[InputDescriptorMapping]] = None,
    ):
        """Initialize InputDescriptorMapping."""
        self.id = id
        self.definition_id = definition_id
        self.descriptor_maps = descriptor_maps


class PresentationSubmissionSchema(BaseModelSchema):
    """Single PresentationSubmission Schema."""

    class Meta:
        """PresentationSubmissionSchema metadata."""

        model_class = PresentationSubmission
        unknown = EXCLUDE

    id = fields.Str(
        required=False,
        metadata={"description": "ID", "example": UUID4_EXAMPLE},
    )
    definition_id = fields.Str(
        required=False,
        metadata={"description": "DefinitionID", "example": UUID4_EXAMPLE},
    )
    descriptor_maps = fields.List(
        fields.Nested(InputDescriptorMappingSchema),
        required=False,
        data_key="descriptor_map",
    )


class FilterEvaluator:
    """Evaluate a filter."""

    def __init__(self, validator: Draft7Validator):
        """Initliaze."""
        self.validator = validator

    @classmethod
    def compile(cls, filter: dict) -> "FilterEvaluator":
        """Compile an input descriptor."""
        Draft7Validator.check_schema(filter)
        validator = Draft7Validator(filter)
        return cls(validator)

    def match(self, value: Any) -> bool:
        """Check value."""
        try:
            self.validator.validate(value)
            return True
        except ValidationError:
            return False


class ConstraintFieldEvaluator:
    """Evaluate a constraint."""

    def __init__(
        self,
        paths: Sequence[JSONPath],
        filter: Optional[FilterEvaluator] = None,
        # TODO Add `name`
    ):
        """Initialize the constraint field evaluator."""
        self.paths = paths
        self.filter = filter

    @classmethod
    def compile(cls, constraint: Union[dict, DIFField]):
        """Compile an input descriptor."""
        if isinstance(constraint, dict):
            constraint = DIFField.deserialize(constraint)
        elif isinstance(constraint, DIFField):
            pass
        else:
            raise TypeError("constraint must be dict or DIFField")

        paths = [jsonpath.parse(path) for path in constraint.paths]

        filter = None
        if constraint._filter:
            filter = FilterEvaluator.compile(constraint._filter.serialize())

        return cls(paths, filter)

    def match(self, value: Any) -> Optional[Matched]:
        """Check if value matches and return path of first matching."""
        matched: Sequence[Matched] = [
            found for path in self.paths for found in path.find(value)
        ]
        if matched and self.filter is not None:
            for match in matched:
                if self.filter.match(match.value):
                    return match
            return None

        if matched:
            return matched[0]

        return None


class DescriptorMatchFailed(Exception):
    """Raised when a Descriptor fails to match."""


class DescriptorEvaluator:
    """Evaluate input descriptors."""

    def __init__(self, id: str, field_constraints: List[ConstraintFieldEvaluator]):
        """Initialize descriptor evaluator."""
        self.id = id
        self._field_constraints = field_constraints

    @classmethod
    def compile(cls, descriptor: Union[dict, InputDescriptors]) -> "DescriptorEvaluator":
        """Compile an input descriptor."""
        if isinstance(descriptor, dict):
            descriptor = InputDescriptors.deserialize(descriptor)
        elif isinstance(descriptor, InputDescriptors):
            pass
        else:
            raise TypeError("descriptor must be dict or InputDescriptor")

        field_constraints = [
            ConstraintFieldEvaluator.compile(constraint)
            for constraint in descriptor.constraint._fields
        ]
        return cls(descriptor.id, field_constraints)

    def match(self, value: Any) -> Dict[str, Any]:
        """Check value."""
        matched_fields = {}
        for constraint in self._field_constraints:
            matched = constraint.match(value)
            if matched is None:
                raise DescriptorMatchFailed("Failed to match descriptor to submission")
            matched_fields[str(matched.full_path)] = matched.value
        return matched_fields


@dataclass
class PexVerifyResult:
    """Result of verification."""

    verified: bool = False
    descriptor_id_to_claims: Dict[str, dict] = field(default_factory=dict)
    descriptor_id_to_fields: Dict[str, Any] = field(default_factory=dict)
    details: Optional[str] = None


class PresentationExchangeEvaluator:
    """Evaluate presentation submissions against presentation definitions."""

    def __init__(self, id: str, descriptors: List[DescriptorEvaluator]):
        """Initialize the evaluator."""
        self.id = id
        self._id_to_descriptor: Dict[str, DescriptorEvaluator] = {
            desc.id: desc for desc in descriptors
        }

    @classmethod
    def compile(cls, definition: Union[dict, PresentationDefinition]):
        """Compile a presentation definition object into evaluatable state."""
        if isinstance(definition, dict):
            definition = PresentationDefinition.deserialize(definition)
        elif isinstance(definition, PresentationDefinition):
            pass
        else:
            raise TypeError("definition must be dict or PresentationDefinition")

        descriptors = [
            DescriptorEvaluator.compile(desc) for desc in definition.input_descriptors
        ]
        return cls(definition.id, descriptors)

    async def verify(
        self,
        profile: Profile,
        submission: Union[dict, PresentationSubmission],
        presentation: Mapping[str, Any],
    ) -> PexVerifyResult:
        """Check if a submission matches the definition."""
        if isinstance(submission, dict):
            submission = PresentationSubmission.deserialize(submission)
        elif isinstance(submission, PresentationSubmission):
            pass
        else:
            raise TypeError("submission must be dict or PresentationSubmission")

        if submission.definition_id != self.id:
            return PexVerifyResult(details="Submission id doesn't match definition")

        descriptor_id_to_claims = {}
        descriptor_id_to_fields = {}
        for item in submission.descriptor_maps or []:
            # TODO Check JWT VP generally, if format is jwt_vp
            evaluator = self._id_to_descriptor.get(item.id)
            if not evaluator:
                return PexVerifyResult(
                    details=f"Could not find input descriptor corresponding to {item.id}"
                )

            processors = profile.inject(CredProcessors)
            if item.path_nested:
                assert item.path_nested.path
                path = jsonpath.parse(item.path_nested.path)
                values = path.find(presentation)
                if len(values) != 1:
                    return PexVerifyResult(
                        details="More than one value found for path "
                        f"{item.path_nested.path}"
                    )

                vc = values[0].value
                processor = processors.cred_verifier_for_format(item.path_nested.fmt)
            else:
                vc = presentation
                processor = processors.cred_verifier_for_format(item.fmt)

            result = await processor.verify_credential(profile, vc)
            if not result.verified:
                return PexVerifyResult(details="Credential signature verification failed")

            try:
                fields = evaluator.match(result.payload)
            except DescriptorMatchFailed:
                return PexVerifyResult(
                    details="Credential did not match expected descriptor constraints"
                )

            descriptor_id_to_claims[item.id] = result.payload
            descriptor_id_to_fields[item.id] = fields

        return PexVerifyResult(
            verified=True,
            descriptor_id_to_claims=descriptor_id_to_claims,
            descriptor_id_to_fields=descriptor_id_to_fields,
        )
