package example
import rego.v1

# 10 days
max_age_ns := 1000000 * 1000 * 60 * 60 * 24 * 10

deny if {
	diff := time.now_ns() - time.parse_rfc3339_ns(input.updated_at)

	diff > max_age_ns
}
