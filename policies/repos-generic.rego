package example

deny[format("HIGH", "Name too short")] {
	count(input.name) < 5
}

deny[format("MEDIUM", "Name too long")] {
	count(input.name) > 8
}

deny[format("LOW", "Public org repo")] {
	input.owner.type == "Organization"
	not input.private
}

format(severity, reason) := { "severity": severity, "reason": reason }
