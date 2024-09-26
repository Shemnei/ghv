package example
import rego.v1

# METADATA
# title: Deny short names
# description: Repo name must be longer than 3 characters
# custom:
#  severity: MEDIUM
result[format(rego.metadata.rule())] if {
	count(input.name) < 3
}

# METADATA
# title: Deny long names
# description: Repo name must not be longer than 8 characters
# custom:
#  severity: HIGH
result[format(rego.metadata.rule())] if {
	count(input.name) > 8
}

format(meta) := {"severity": meta.custom.severity, "reason": meta.description}
