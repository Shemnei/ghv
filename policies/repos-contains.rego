package example

deny contains { "reason": "Name too short" } if {
	count(input.name) < 5
}

deny contains { "reason": "Name too long" } if {
	count(input.name) > 8
}
