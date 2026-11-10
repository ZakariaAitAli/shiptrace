"""R11: an event's service and environment must equal the credential's binding (spec §3, AC7).

The rule is a pure comparison of two pairs of slugs. It takes no deployment, no registry and no
store, so its answer cannot depend on whether the target exists."""

import inspect
import unicodedata

import pytest

from shiptrace.domain.deployments import binding_matches

CYRILLIC_A = chr(0x0430)
E_ACUTE = chr(0x00E9)


def test_matching_pair() -> None:
    assert binding_matches("payments-api", "production", "payments-api", "production") is True


@pytest.mark.parametrize(
    ("service", "environment"),
    [
        ("billing-api", "production"),  # another service
        ("payments-api", "staging"),  # another environment
        ("billing-api", "staging"),  # both
        ("production", "payments-api"),  # the two values swapped
        ("Payments-api", "production"),  # case is not folded
        ("payments-api", "Production"),
        ("payments", "production"),  # a prefix
        ("payments-api-2", "production"),  # an extension
        ("payments-api", "prod"),
        ("payments-api ", "production"),  # whitespace
        ("payments-api", "production\n"),
        ("payments-api\n", "production"),
        ("", "production"),
        ("payments-api", ""),
        ("", ""),
        ("p" + CYRILLIC_A + "yments-api", "production"),  # a look-alike character
    ],
)
def test_any_difference_is_a_mismatch(service: str, environment: str) -> None:
    assert binding_matches("payments-api", "production", service, environment) is False


def test_each_slot_is_compared_with_its_own_binding() -> None:
    assert binding_matches("a", "b", "a", "b")
    assert not binding_matches("a", "b", "b", "a")
    assert not binding_matches("a", "a", "a", "b")
    assert not binding_matches("a", "b", "a", "a")


def test_unicode_is_not_normalized() -> None:
    composed = "caf" + E_ACUTE
    decomposed = unicodedata.normalize("NFD", composed)
    assert composed != decomposed
    assert not binding_matches(composed, "production", decomposed, "production")
    assert binding_matches(composed, "production", composed, "production")


def test_the_comparison_takes_slugs_only_so_it_cannot_depend_on_the_target_existing() -> None:
    names = list(inspect.signature(binding_matches).parameters)
    assert names == ["bound_service", "bound_environment", "service", "environment"]
