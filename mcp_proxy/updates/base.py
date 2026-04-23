"""Base class for federation update migrations.

A migration represents a breaking change to state the proxy owns
(cert format, keys, schema). The boot detector finds subclasses of
:class:`Migration`, calls :meth:`check` to decide whether they apply,
and surfaces the pending ones in the dashboard. The admin drives
apply / rollback via :meth:`up` / :meth:`rollback`.

The five allowed ``migration_type`` values mirror the taxonomy in
``imp/federation_hardening_plan.md`` Parte 1:

- ``cert-schema``    — existing certs are format-invalid but their
                       pubkey can be preserved (e.g. pathLen fix #280).
- ``cert-algorithm`` — existing keys are cryptographically obsolete,
                       re-enrollment is forced (e.g. RSA → Ed25519).
- ``policy-change``  — toggle a runtime policy (e.g. DPoP mandatory).
- ``new-feature``    — additive; existing state untouched.
- ``code-refactor``  — no state change, info banner only.

``criticality`` drives the degraded-mode decision at boot. ``critical``
plus any overlap between ``affects_enrollments`` and the enrollments
currently active puts the proxy in sign-halt (PR 2 behaviour, same
primitive as ADR-012 staged rotation).

Idempotency contract — both :meth:`up` and :meth:`rollback` MUST be
safe to call repeatedly on the same target state. The admin UI (PR 5)
retries on transient failures and the operator may re-run after a
manual intervention. Non-idempotent migrations are a release-blocker.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar


_ALLOWED_TYPES: frozenset[str] = frozenset({
    "cert-schema",
    "cert-algorithm",
    "policy-change",
    "new-feature",
    "code-refactor",
})

_ALLOWED_CRITICALITY: frozenset[str] = frozenset({
    "critical",
    "warning",
    "info",
})

_ALLOWED_ENROLLMENTS: frozenset[str] = frozenset({
    "connector",
    "byoca",
    "spire",
})

_REQUIRED_CLASSATTRS: tuple[str, ...] = (
    "migration_id",
    "migration_type",
    "criticality",
    "description",
    "preserves_enrollments",
    "affects_enrollments",
)


class Migration(ABC):
    """Abstract base for every concrete migration in the registry.

    Concrete subclasses MUST set the following class attributes. Missing
    or mistyped attributes raise :class:`TypeError` at subclass
    definition time so bad migrations fail loud during import, not at
    boot-detection time when the dashboard is the only surface.

    Attributes:
        migration_id: stable identifier, data-prefixed lexical sort key.
            Convention: ``YYYY-MM-DD-slug`` (e.g.
            ``"2026-04-23-org-ca-pathlen-1"``).
        migration_type: one of
            ``cert-schema | cert-algorithm | policy-change |
            new-feature | code-refactor``.
        criticality: ``critical | warning | info``. Drives degraded
            mode at boot.
        description: one-line human prose explaining what the migration
            does and why. Rendered verbatim in the dashboard table; keep
            it operator-readable, no Python jargon.
        preserves_enrollments: True iff ``up`` preserves agent pubkeys
            (re-sign leaves) vs forcing re-enrollment.
        affects_enrollments: enrollments touched by ``up``; subset of
            ``("connector", "byoca", "spire")``. Empty tuple means the
            migration is enrollment-agnostic (rare).
    """

    migration_id: ClassVar[str]
    migration_type: ClassVar[str]
    criticality: ClassVar[str]
    description: ClassVar[str]
    preserves_enrollments: ClassVar[bool]
    affects_enrollments: ClassVar[tuple[str, ...]]

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)

        # Contract enforcement runs on every subclass — ABCMeta populates
        # ``__abstractmethods__`` *after* ``__init_subclass__`` returns,
        # so skipping abstract helpers here is unreliable. A helper that
        # doesn't implement ``check``/``up``/``rollback`` can still
        # declare sensible class-attr defaults (e.g. migration_id =
        # "__shared_base__") and pass the contract; that keeps the
        # enforcement semantics one-line.
        missing = [
            name for name in _REQUIRED_CLASSATTRS
            if name not in cls.__dict__ and not any(
                name in base.__dict__ for base in cls.__mro__[1:-1]
            )
        ]
        if missing:
            raise TypeError(
                f"{cls.__name__} is missing required class attributes: "
                f"{', '.join(missing)}"
            )

        if cls.migration_type not in _ALLOWED_TYPES:
            raise TypeError(
                f"{cls.__name__}.migration_type = {cls.migration_type!r} "
                f"not in {sorted(_ALLOWED_TYPES)}"
            )
        if cls.criticality not in _ALLOWED_CRITICALITY:
            raise TypeError(
                f"{cls.__name__}.criticality = {cls.criticality!r} "
                f"not in {sorted(_ALLOWED_CRITICALITY)}"
            )
        if not isinstance(cls.affects_enrollments, tuple):
            raise TypeError(
                f"{cls.__name__}.affects_enrollments must be a tuple, "
                f"got {type(cls.affects_enrollments).__name__}"
            )
        unknown = [
            e for e in cls.affects_enrollments if e not in _ALLOWED_ENROLLMENTS
        ]
        if unknown:
            raise TypeError(
                f"{cls.__name__}.affects_enrollments has unknown values: "
                f"{unknown}; allowed: {sorted(_ALLOWED_ENROLLMENTS)}"
            )
        if not isinstance(cls.preserves_enrollments, bool):
            raise TypeError(
                f"{cls.__name__}.preserves_enrollments must be bool, "
                f"got {type(cls.preserves_enrollments).__name__}"
            )
        if not isinstance(cls.description, str) or not cls.description.strip():
            raise TypeError(
                f"{cls.__name__}.description must be a non-empty string"
            )
        if not isinstance(cls.migration_id, str) or not cls.migration_id.strip():
            raise TypeError(
                f"{cls.__name__}.migration_id must be a non-empty string"
            )

    @abstractmethod
    async def check(self) -> bool:
        """Return True iff this migration is pending against current state.

        Called by the boot detector (PR 2) on every startup. Must be
        read-only: idempotent, side-effect-free, safe to call under load.

        Exceptions raised here are **detection errors**, not a negative
        result. The boot detector catches them, logs WARNING, and does
        NOT insert a row into ``pending_updates`` for this migration —
        the migration will be re-evaluated on the next boot. Concrete
        migrations should therefore only raise for genuinely unexpected
        conditions (DB unreachable, corrupt config) and return ``False``
        for "not applicable to this proxy".
        """

    @abstractmethod
    async def up(self) -> None:
        """Apply the migration.

        MUST be idempotent — a second call on an already-applied target
        is a no-op, not an error. The admin UI retries on transient
        failure; the operator may re-run after a manual intervention.

        Raises on non-recoverable errors; the caller (PR 4 endpoint)
        records ``status='failed'`` with the exception message.
        """

    @abstractmethod
    async def rollback(self) -> None:
        """Revert the migration.

        MUST be idempotent. May raise if the backup referenced by the
        migration has expired or was never created (some migrations are
        irreversible by design — ``cert-algorithm`` typically is, since
        old keys are cryptographically obsolete). Concrete migrations
        document whether rollback is supported in their docstring.
        """
