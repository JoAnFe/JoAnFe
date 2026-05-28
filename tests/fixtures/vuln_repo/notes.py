"""A benign file used to exercise the evidence-less -> appendix path.

The scripted fake emits a candidate here but produces a finding with no
preconditions/reachability/citation, so it must be routed to the appendix by
the hard evidence gate.
"""


def add(a, b):
    return a + b
