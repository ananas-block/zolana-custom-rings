package transfer

// Shape sizes a key, Inputs also bounds the signers it can bind.
type Shape struct {
	Inputs, Outputs, Withdrawals, Owners int
	Entry                                bool
	// Wide fits a salted and a public record per owner.
	Wide bool
}

// Shapes mirrors TRANSFER_SHAPES in program-libs/interface/src/proof/key_catalog.rs.
var Shapes = [...]Shape{
	{Inputs: 24, Outputs: 2, Withdrawals: 4, Owners: 4},
	{Inputs: 24, Outputs: 4, Withdrawals: 4, Owners: 4},
	{Inputs: 16, Outputs: 8, Withdrawals: 4, Owners: 4},
	{Inputs: 5, Outputs: 16, Withdrawals: 8, Owners: 5},
	{Inputs: 24, Outputs: 8, Withdrawals: 32, Owners: 24, Wide: true},
	{Inputs: 5, Outputs: 16, Withdrawals: 8, Owners: 5, Wide: true},
	{Inputs: 8, Outputs: 16, Withdrawals: 8, Owners: 8, Wide: true},
	{Inputs: 49, Outputs: 2, Withdrawals: 4, Owners: 12, Wide: true},
	{Inputs: 8, Outputs: 4, Withdrawals: 4, Owners: 8, Entry: true, Wide: true},
	{Inputs: 2, Outputs: 8, Withdrawals: 4, Owners: 2, Entry: true, Wide: true},
	{Inputs: 4, Outputs: 8, Withdrawals: 4, Owners: 4, Entry: true, Wide: true},
	{Inputs: 24, Outputs: 2, Withdrawals: 32, Owners: 12, Entry: true, Wide: true},
}
