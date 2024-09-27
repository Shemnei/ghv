package repos

deny contains sprintf("Bad default branch `%s`", [input.default_branch]) {
	input.default_branch != "main"
}

deny contains sprintf("Unlicensed public repository `%s`", [input.name]) {
	not input.license
	not input.private
}
