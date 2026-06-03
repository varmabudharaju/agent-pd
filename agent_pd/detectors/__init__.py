from . import (permission_bypass, out_of_scope, redundant, off_task,
               self_permission, tool_scope)

DETECTORS = {
    "permission_bypass": permission_bypass,
    "out_of_scope": out_of_scope,
    "redundant": redundant,
    "off_task": off_task,
    "self_permission": self_permission,
    "tool_not_allowed": tool_scope,
}


def run_detectors(record, rules) -> list:
    out = []
    for name, module in DETECTORS.items():
        if rules.detectors.get(name, True):
            out.extend(module.detect(record, rules))
    return out
