from aries_cloudagent.core.profile import Profile, ProfileSession

from aries_cloudagent.config.injection_context import InjectionContext


class KafkaProfile(Profile):
    def __init__(self, context: InjectionContext = None):
        """Initialize a base profile."""
        self._context = context or InjectionContext()
        self._created = True
        self._name = "kafka_consumer"

    def session(self, context: InjectionContext = None) -> "ProfileSession":
        """Start a new interactive session with no transaction support requested."""
        return KafkaProfileSession(self, context=context)

    def transaction(self, context: InjectionContext = None) -> "ProfileSession":
        """
        Start a new interactive session with commit and rollback support.

        If the current backend does not support transactions, then commit
        and rollback operations of the session will not have any effect.
        """
        return KafkaProfileSession(self, context=context)


class KafkaProfileSession(ProfileSession):
    """An active connection to the profile management backend."""

    def __init__(self, profile: Profile, context: InjectionContext = None):
        """Create a new InMemoryProfileSession instance."""
        super().__init__(profile=profile, context=context)
