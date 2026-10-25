package policy

// Table capacities, mirrored by program-libs/policy/src/rule_table/mod.rs.
const (
	NRules   = 16
	NSources = 8
)

// Policy table hash layout, mirrored by EncodedRuleTable::hash in program-libs/policy/src/rule_table/mod.rs.
const (
	// PolicyTableVersion enters the table hash, every layout change bumps it.
	PolicyTableVersion = 12
	PolicyTableFields  = 44
	// PolicyTableRate fields join the accumulator per Poseidon call, twelve inputs is the syscall maximum.
	PolicyTableRate = 11
)

// Every table hash call absorbs a full rate of fields.
const _ = uint(-(PolicyTableFields % PolicyTableRate))

// Rule row values, mirrored by Subject, Mode and the guard tags of Rule::encoded in program-libs/policy/src/rule_table/mod.rs.
const (
	SubjectOutputOwner = 1
	SubjectSender      = 2
	SubjectAsset       = 4

	ModePresent = 1
	ModeAbsent  = 2

	GuardAlways             = 0
	GuardAboveAmount        = 1
	GuardAboveAmountByAsset = 2
)
