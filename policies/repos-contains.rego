package repos

deny contains { "reason": "Name too short", "context": { "name": input.name } } if {
	count(input.name) < 5
}

deny contains { "reason": "Name too long", "context": { "name": input.name } } if {
	count(input.name) > 8
}
