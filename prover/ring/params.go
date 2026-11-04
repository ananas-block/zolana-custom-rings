package ring

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Request fields carry the circuit field names, their tags the wire names.

type RequestHead struct {
	CircuitType     common.CircuitType `json:"circuitType"`
	PublicInputHash Field              `json:"publicInputHash"`
}

func (h RequestHead) head() RequestHead { return h }

type headed interface {
	head() RequestHead
}

type Opening struct {
	Domain        Field `json:"domain"`
	TreeID        Field `json:"treeId"`
	OwnerPkHash   Field `json:"ownerPkHash"`
	NullifierPk   Field `json:"nullifierPk"`
	Asset         Field `json:"asset"`
	Amount        Field `json:"amount"`
	Blinding      Field `json:"blinding"`
	DataHash      Field `json:"dataHash"`
	RingDataHash  Field `json:"ringDataHash"`
	RingProgramID Field `json:"ringProgramId"`
}

// AuditParams are the envelope wires of a transfer, the ring id sits beside the policy values.
type AuditParams struct {
	FirstNullifier Field `json:"firstNullifier"`
	TxViewingSk    Bytes `json:"txViewingSk"`
	EphSk          Bytes `json:"ephSk"`
	AuditorPk      Bytes `json:"auditorPk"`
	Salt           Bytes `json:"salt"`
	Layout         uint8 `json:"layout"`
}

// OutputOpening is one output slot and the preimages its record names.
type OutputOpening struct {
	Output     Opening `json:"output"`
	OwnerKey   Bytes   `json:"ownerKey"`
	MintChunks []Field `json:"mintChunks"`
}

// EntryOpening names a default-ring input's preimages, zero off one.
type EntryOpening struct {
	OwnerKey   Bytes   `json:"ownerKey"`
	MintChunks []Field `json:"mintChunks"`
}

// TrackingRecordParams is one opened tracking leaf.
type TrackingRecordParams struct {
	Member      Field `json:"member"`
	Next        Field `json:"next"`
	NullifierPk Field `json:"nullifierPk"`
	CtHash      Field `json:"ctHash"`
	View0       Field `json:"view0"`
	View1       Field `json:"view1"`
	Revision    Field `json:"revision"`
	ListTag     Field `json:"listTag"`
}

// TrackingParams opens every owner row and live ring output under the frame's tracking root.
type TrackingParams struct {
	TrackingRoot     Field                  `json:"trackingRoot"`
	TrackingRecords  []TrackingRecordParams `json:"trackingRecords"`
	TrackingProof    SharedRegistryProof    `json:"trackingProof"`
	TrackingSubjects []PooledSubject        `json:"trackingSubjects"`
	RowEntries       []uint32               `json:"rowEntries"`
	OutputEntries    []uint32               `json:"outputEntries"`
}

// TransferParams is what every transfer key reads, the rail's own values follow in its family's params.
type TransferParams struct {
	RequestHead
	AuditParams
	ApprovalMask      uint8           `json:"approvalMask"`
	OutputCount       uint8           `json:"outputCount"`
	Outputs           []OutputOpening `json:"outputs"`
	InputCount        uint8           `json:"inputCount"`
	Inputs            []Opening       `json:"inputs"`
	Entries           []EntryOpening  `json:"entries,omitempty"`
	SignerCount       uint8           `json:"signerCount"`
	Signers           []Field         `json:"signers"`
	Rows              []Field         `json:"rows"`
	PrivateTxHash     Field           `json:"privateTxHash"`
	PrivateTxBlinding Field           `json:"privateTxBlinding"`
	PrivateRoot       Field           `json:"privateRoot"`
	TrackingParams
	PolicyParams
}

type ConfidentialTransferParams struct {
	TransferParams
	InProof  bool `json:"inProof"`
	Delegate bool `json:"delegate"`
	// Sender is the in-proof owner, zero on the signer and authority rails.
	Sender Field `json:"sender"`
}

type AnonymousTransferParams struct {
	TransferParams
	PublicOwners bool `json:"publicOwners"`
	Delegate     bool `json:"delegate"`
	// PartyIdentities are payer, five co-signers and exit destination, zero when absent.
	PartyIdentities []Field `json:"partyIdentities"`
}

type Source struct {
	ListID uint8 `json:"listId"`
	// Registry is zero for a list the ring's own registry serves, else the curator registry address.
	Registry Field `json:"registry"`
}

type PolicyTable struct {
	Sources   []Source `json:"sources"`
	PolicyLen uint8    `json:"policyLen"`
	Rules     []Field  `json:"rules"`
}

// RecordOpening opens a member's record in a member registry, Path the three siblings of every level from the leaf up in child order.
type RecordOpening struct {
	Next                Field   `json:"next"`
	Lists               uint64  `json:"lists"`
	MintPolicy          Field   `json:"mintPolicy"`
	WithdrawalThreshold Field   `json:"withdrawalThreshold"`
	AssetLimits         []Field `json:"assetLimits"`
	Index               uint64  `json:"index"`
	Path                []Field `json:"path"`
}

// MemberOpening proves a member present, or absent under its low record, nil only for a slot that is no live UTXO.
type MemberOpening struct {
	Present bool `json:"present"`
	RecordOpening
	LowMember              Field   `json:"lowMember"`
	LowNext                Field   `json:"lowNext"`
	LowLists               uint64  `json:"lowLists"`
	LowMintPolicy          Field   `json:"lowMintPolicy"`
	LowWithdrawalThreshold Field   `json:"lowWithdrawalThreshold"`
	LowAssetLimits         []Field `json:"lowAssetLimits"`
}

type Withdrawal struct {
	Owner  Field `json:"owner"`
	Asset  Field `json:"asset"`
	Amount Field `json:"amount"`
}

type PolicyInputsParams struct {
	WithdrawalCount uint8        `json:"withdrawalCount"`
	WithdrawalHash  Field        `json:"withdrawalHash"`
	Withdrawals     []Withdrawal `json:"withdrawals"`
	PolicyHash      Field        `json:"policyHash"`
	RingProgramID   Field        `json:"ringId"`
	OwnRoot         Field        `json:"ownRoot"`
	CuratorRoot     Field        `json:"curatorRoot"`
	PublicAssets    []Field      `json:"publicAssets"`
	PublicAmounts   []Field      `json:"publicAmounts"`
	PublicGross     []Field      `json:"publicGross"`
	PolicyTable
}

type PooledRecord struct {
	Member              Field   `json:"member"`
	Next                Field   `json:"next"`
	Lists               uint64  `json:"lists"`
	MintPolicy          Field   `json:"mintPolicy"`
	WithdrawalThreshold Field   `json:"withdrawalThreshold"`
	AssetLimits         []Field `json:"assetLimits"`
}

type PooledSubject struct {
	Member      Field  `json:"member"`
	RecordIndex uint32 `json:"recordIndex"`
}

type PooledEntry struct {
	Own     uint32   `json:"own"`
	Curator []uint32 `json:"curator"`
}

type SharedRegistryPath struct {
	Index    uint32    `json:"index"`
	Siblings [][]Field `json:"siblings"`
}

type SharedRegistryProof struct {
	Canopy []Field              `json:"canopy"`
	Paths  []SharedRegistryPath `json:"paths"`
}

type PolicyParams struct {
	PolicyInputsParams
	OwnRecords      []PooledRecord      `json:"ownRecords"`
	CuratorRecords  []PooledRecord      `json:"curatorRecords"`
	OwnProof        SharedRegistryProof `json:"ownProof"`
	CuratorProof    SharedRegistryProof `json:"curatorProof"`
	OwnSubjects     []PooledSubject     `json:"ownSubjects"`
	CuratorSubjects []PooledSubject     `json:"curatorSubjects"`
	SenderEntries   []PooledEntry       `json:"senderEntries"`
	// OwnerEntries[o] and AssetEntries[o] index payment o's owner and asset subjects.
	OwnerEntries       []PooledEntry `json:"ownerEntries"`
	AssetEntries       []PooledEntry `json:"assetEntries"`
	PublicAssetEntries []uint32      `json:"publicAssetEntries"`
}

type QueueEntry struct {
	Member              Field   `json:"member"`
	Mask                uint64  `json:"mask"`
	Value               uint64  `json:"value"`
	MintPolicy          Field   `json:"mintPolicy"`
	WithdrawalThreshold Field   `json:"withdrawalThreshold"`
	AssetLimits         []Field `json:"assetLimits"`
}

type RecordWrite struct {
	Entry                  QueueEntry `json:"entry"`
	Exists                 bool       `json:"exists"`
	OldNext                Field      `json:"oldNext"`
	OldLists               uint64     `json:"oldLists"`
	OldMintPolicy          Field      `json:"oldMintPolicy"`
	OldWithdrawalThreshold Field      `json:"oldWithdrawalThreshold"`
	OldAssetLimits         []Field    `json:"oldAssetLimits"`
	// Index and Path open the member's leaf or the leaf an insert takes.
	Index                  uint64  `json:"index"`
	Path                   []Field `json:"path"`
	LowMember              Field   `json:"lowMember"`
	LowNext                Field   `json:"lowNext"`
	LowLists               uint64  `json:"lowLists"`
	LowMintPolicy          Field   `json:"lowMintPolicy"`
	LowWithdrawalThreshold Field   `json:"lowWithdrawalThreshold"`
	LowAssetLimits         []Field `json:"lowAssetLimits"`
	// LowIndex and LowPath open the low record.
	LowIndex uint64  `json:"lowIndex"`
	LowPath  []Field `json:"lowPath"`
}

type ApplyRecordsParams struct {
	RequestHead
	OldRoot      Field  `json:"oldRoot"`
	NewRoot      Field  `json:"newRoot"`
	OldNextIndex uint32 `json:"oldNextIndex"`
	NewNextIndex uint32 `json:"newNextIndex"`
	ChainStart   Field  `json:"chainStart"`
	ChainEnd     Field  `json:"chainEnd"`
	Count        uint8  `json:"count"`
	// A nil write past Count assigns zeros.
	Writes []*RecordWrite `json:"writes"`
}

// TrackingWrite is the witness of one applied entry.
type TrackingWrite struct {
	Member      Field                `json:"member"`
	NullifierPk Field                `json:"nullifierPk"`
	CtHash      Field                `json:"ctHash"`
	View0       Field                `json:"view0"`
	View1       Field                `json:"view1"`
	Revision    Field                `json:"revision"`
	ListTag     Field                `json:"listTag"`
	Exists      bool                 `json:"exists"`
	OldRecord   TrackingRecordParams `json:"oldRecord"`
	Index       uint64               `json:"index"`
	Path        []Field              `json:"path"`
	LowRecord   TrackingRecordParams `json:"lowRecord"`
	LowIndex    uint64               `json:"lowIndex"`
	LowPath     []Field              `json:"lowPath"`
}

type ApplyEnrollmentsParams struct {
	RequestHead
	OldRoot      Field  `json:"oldRoot"`
	NewRoot      Field  `json:"newRoot"`
	OldNextIndex uint32 `json:"oldNextIndex"`
	NewNextIndex uint32 `json:"newNextIndex"`
	ChainStart   Field  `json:"chainStart"`
	ChainEnd     Field  `json:"chainEnd"`
	Count        uint8  `json:"count"`
	// A nil write past Count assigns zeros.
	Writes []*TrackingWrite `json:"writes"`
}

type RegisterKeyParams struct {
	RequestHead
	RingID          Field `json:"ringId"`
	Member          Field `json:"member"`
	NullifierSecret Bytes `json:"nullifierSecret"`
	EphSk           Bytes `json:"ephSk"`
	AuditorPk       Bytes `json:"auditorPk"`
}

type DepositParams struct {
	RequestHead
	ContextHash     Field   `json:"contextHash"`
	Count           uint32  `json:"count"`
	Anonymous       bool    `json:"anonymous,omitempty"`
	OwnerPkHashes   []Field `json:"ownerPkHashes"`
	OwnerKeys       []Bytes `json:"ownerKeys"`
	NullifierPks    []Field `json:"nullifierPks"`
	BlindingSecrets []Field `json:"blindingSecrets"`
	EphSk           Bytes   `json:"ephSk"`
	AuditorPk       Bytes   `json:"auditorPk"`
	TrackingRoot    Field   `json:"trackingRoot"`
	// Tracking is nil at a padding slot.
	Tracking    []*TrackingOpening `json:"tracking"`
	OwnRoot     Field              `json:"ownRoot"`
	CuratorRoot Field              `json:"curatorRoot"`
	PolicyHash  Field              `json:"policyHash"`
	Assets      []Field            `json:"assets"`
	Amounts     []Field            `json:"amounts"`
	MintChunks  [][]Field          `json:"mintChunks"`
	// Table and the records are absent without a written policy, the curator records also without a curator source.
	Table               *PolicyTable     `json:"table,omitempty"`
	AssetRecords        []*MemberOpening `json:"assetRecords"`
	OwnerRecords        []*MemberOpening `json:"ownerRecords"`
	CuratorAssetRecords []*MemberOpening `json:"curatorAssetRecords"`
	CuratorOwnerRecords []*MemberOpening `json:"curatorOwnerRecords"`
}

// TrackingLeaf mirrors registry.TrackingRecord field for field.
type TrackingLeaf struct {
	Member      Field `json:"member"`
	Next        Field `json:"next"`
	NullifierPk Field `json:"nullifierPk"`
	CtHash      Field `json:"ctHash"`
	View0       Field `json:"view0"`
	View1       Field `json:"view1"`
	Revision    Field `json:"revision"`
	ListTag     Field `json:"listTag"`
}

// TrackingOpening mirrors registry.TrackingOpening field for field.
type TrackingOpening struct {
	Present bool               `json:"present"`
	Record  TrackingLeaf       `json:"record"`
	Path    SharedRegistryPath `json:"path"`
}

// MergeParams seals a ring's SPP merge output to its auditor, Tracking is nil under a zero key.
type MergeParams struct {
	RequestHead
	OutputUtxoHash     Field            `json:"outputUtxoHash"`
	FirstNullifier     Field            `json:"firstNullifier"`
	RingProgramID      Field            `json:"ringProgramId"`
	AuditorPk          Bytes            `json:"auditorPk"`
	Payer              Field            `json:"payer"`
	TrackingRoot       Field            `json:"trackingRoot"`
	EphSk              Bytes            `json:"ephSk"`
	OwnerKey           Bytes            `json:"ownerKey"`
	Mint               Bytes            `json:"mint"`
	Amount             Field            `json:"amount"`
	NullifierPk        Field            `json:"nullifierPk"`
	Seed               Field            `json:"seed"`
	OutputTreeID       Field            `json:"outputTreeId"`
	OutputRingDataHash Field            `json:"outputRingDataHash"`
	Tracking           *TrackingOpening `json:"tracking"`
}

// Unmarshal refuses an unknown or repeated key, a missing key without omitempty and trailing data.
func Unmarshal(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := strictly(decoder, reflect.TypeOf(v).Elem(), 0); err != nil {
		return fmt.Errorf("custom-ring: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("custom-ring: trailing data after the request")
	}
	return json.Unmarshal(data, v)
}

const maxDepth = 32

var unmarshaler = reflect.TypeFor[json.Unmarshaler]()

// strictly reads one value of t, refusing a key without an exact field, a repeated key and a null t cannot hold.
func strictly(decoder *json.Decoder, t reflect.Type, depth int) error {
	if depth > maxDepth {
		return errors.New("nested too deeply")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	nullable := t.Kind() == reflect.Pointer
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	custom := reflect.PointerTo(t).Implements(unmarshaler)
	if token == nil {
		if nullable || custom {
			return nil
		}
		return errors.New("null value")
	}
	if !custom {
		switch t.Kind() {
		case reflect.Struct:
			return strictObject(decoder, t, token, depth)
		case reflect.Slice, reflect.Array:
			return strictArray(decoder, t, token, depth)
		}
	}
	if _, composite := token.(json.Delim); composite {
		return errors.New("expected a scalar")
	}
	return nil
}

func strictObject(decoder *json.Decoder, t reflect.Type, token json.Token, depth int) error {
	if token != json.Delim('{') {
		return errors.New("expected an object")
	}
	fields := jsonFields(t, nil)
	byName := make(map[string]jsonField, len(fields))
	for _, field := range fields {
		byName[field.name] = field
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		name, _ := key.(string)
		field, known := byName[name]
		if !known {
			return fmt.Errorf("unknown field %q", name)
		}
		if seen[name] {
			return fmt.Errorf("repeated field %q", name)
		}
		seen[name] = true
		if err := strictly(decoder, field.typ, depth+1); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	for _, field := range fields {
		if !field.optional && !seen[field.name] {
			return fmt.Errorf("missing field %q", field.name)
		}
	}
	return nil
}

func strictArray(decoder *json.Decoder, t reflect.Type, token json.Token, depth int) error {
	if token != json.Delim('[') {
		return errors.New("expected an array")
	}
	for i := 0; decoder.More(); i++ {
		if err := strictly(decoder, t.Elem(), depth+1); err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}
	}
	_, err := decoder.Token()
	return err
}

type jsonField struct {
	name     string
	typ      reflect.Type
	optional bool
}

// jsonFields promotes untagged embedded structs as encoding/json does.
func jsonFields(t reflect.Type, fields []jsonField) []jsonField {
	for i := range t.NumField() {
		field := t.Field(i)
		name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
		if field.Anonymous && name == "" && field.Type.Kind() == reflect.Struct {
			fields = jsonFields(field.Type, fields)
			continue
		}
		if name == "-" || !field.IsExported() {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields = append(fields, jsonField{name: name, typ: field.Type, optional: slices.Contains(strings.Split(options, ","), "omitempty")})
	}
	return fields
}
