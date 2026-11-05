use std::collections::BTreeMap;

use custom_ring_interface::{
    storage::StorageError,
    CustomRingError::{self, *},
};

macro_rules! pinned_codes {
    ($($variant:ident = $code:literal,)*) => {
        /// A new variant fails to compile until pinned here.
        fn pinned_code(error: CustomRingError) -> u32 {
            match error {
                $($variant => $code,)*
            }
        }

        const VARIANTS: &[CustomRingError] = &[$($variant,)*];
    };
}

pinned_codes! {
    InvalidInstructionData = 8100,
    ProofVerificationFailed = 8101,
    HashingFailed = 8102,
    InvalidShieldedPoolProgram = 8103,
    MissingRingAuth = 8104,
    UnauthorizedAuthority = 8107,
    InvalidAuditorPubkey = 8108,
    InvalidSystemProgram = 8111,
    UnsupportedCircuit = 8113,
    UnauthorizedInitializer = 8114,
    TooManyAccounts = 8115,
    InvalidListId = 8126,
    InvalidSource = 8134,
    InvalidPolicyRules = 8140,
    PolicyGenerationOverflow = 8141,
    PolicyOnAuditOnlyRing = 8142,
    MissingCoSigner = 8143,
    UnauthorizedCoSigner = 8144,
    InvalidCoSignerScope = 8145,
    InvalidCoSigner = 8146,
    DelegateDisabled = 8150,
    UnauthorizedDelegate = 8151,
    DelegatePublicLeg = 8152,
    DelegateAlreadySet = 8153,
    InvalidDepositDisclosure = 8166,
    MissingFundingSigner = 8173,
    InvalidRingMode = 8174,
    InvalidAnonymousSigner = 8178,
    InvalidMergeDisclosure = 8179,
    InvalidDepositData = 8180,
    MissingOwnerSigner = 8192,
    RingTransactLength = 8200,
    RingShapeUnkeyed = 8201,
    FlagNotAllowed = 8202,
    OwnerSignerCount = 8208,
    MemberOutOfRange = 8209,
    ListBitNotWritable = 8210,
    ValueOutsideMask = 8211,
    AuthorityBatchTooLarge = 8214,
    PolicyNotSet = 8217,
    InvalidSppProofPoint = 8218,
    ZeroPublicLegAmount = 8225,
    TooManyPublicAssets = 8226,
    PublicAmountOverflow = 8227,
    ZeroNetPublicAmount = 8228,
    MissingPolicyProof = 8229,
    UnexpectedPolicyProof = 8230,
    CoSignerIsOwner = 8231,
    MemberWrittenListRule = 8233,
    RingAuthOutOfSlot = 8234,
    InvalidRingProofPoint = 8238,
    UnexpectedMemberRegistryRoot = 8240,
    UnexpectedApproval = 8241,
    InvalidSettlementAccounts = 8242,
    TooManyPublicLegs = 8243,
    InvalidAuditedDeposit = 8244,
    AnonymousExitDestinationsDiffer = 8246,
    AnonymousExitTokenAccountShared = 8247,
    AnonymousExitAccountHasData = 8248,
    AnonymousExitTokenAccountOnCurve = 8249,
    AnonymousExitTokenAccountInvalid = 8250,
    OutputBodyLength = 8253,
    OutputCountOutOfRange = 8257,
    BodilessExit = 8258,
    ReplyLength = 8259,
    RecordsRegistryOtherRing = 8266,
    ListNotPolicyReadable = 8255,
    MultiListAbsenceRule = 8235,
    InvertedListPolarity = 8236,
    MixedPolarityRule = 8237,
    InvalidCoSignerRecord = 8260,
    CoSignerRecordAlreadyExists = 8261,
    CoSignerOutOfScope = 8262,
    CoSignerCountOutOfRange = 8263,
    InvalidRingPolicy = 8300,
    RingPolicyAlreadyExists = 8301,
    InvalidStorageRegistry = 8302,
    InvalidAssetLimits = 8390,
    DepositMintAccountMissing = 8410,
    DepositAssetIndexUnknown = 8411,
    UnexpectedCuratorRevision = 8470,
    ZeroRoleKey = 8471,
    DuplicateRoleKey = 8472,
    UnboundRegistry = 8480,
    RootNotServed = 8481,
    MissingRegistry = 8482,
    InvalidTrackingRegistry = 8502,
    TrackingRootBelowFloor = 8503,
    SaltedSourceOtherTracking = 8504,
    InvalidFrameBuffer = 8520,
    FrameLength = 8521,
    UnauthorizedFrameWriter = 8522,
    FrameDigestMismatch = 8523,
    FrameWriteOutOfRange = 8524,
    UnsupportedBufferedTag = 8525,
    FramePayerNotWriter = 8526,
    InvalidSignerDataCounts = 8527,
    TooManyAnonymousParties = 8528,
    InvalidCredentialPda = 8529,
    InvalidEnrollmentAccounts = 8530,
    InvalidAddressTree = 8531,
    InvalidCredentialRead = 8532,
    InvalidCredentialRoots = 8533,
    InvalidAddressCheckpoint = 8534,
    AbsenceRootBelowFloor = 8535,
    SaltedSourceOtherRing = 8536,
    TooManyDepositsForKey = 8537,
}

#[test]
fn error_codes_are_stable() {
    for &error in VARIANTS {
        assert_eq!(error as u32, pinned_code(error), "{error:?}");
    }
    let fixture: BTreeMap<String, u32> = serde_json::from_str(include_str!(
        "../../../test-vectors/errors/custom-ring-errors.json"
    ))
    .unwrap();
    let actual = VARIANTS
        .iter()
        .map(|&error| (format!("{error:?}"), error as u32))
        .collect();
    assert_eq!(fixture, actual, "shared error code fixture drifted");
}

#[test]
fn storage_error_codes_are_stable() {
    use StorageError as Error;
    let pins = [
        (Error::InvalidRegistry, 9000),
        (Error::Unauthorized, 9001),
        (Error::RevisionChanged, 9002),
        (Error::RootExpired, 9003),
        (Error::HistoryFull, 9004),
        (Error::InvalidInstructionData, 9005),
        (Error::BatchTooLarge, 9006),
        (Error::InvalidWrite, 9007),
        (Error::ProofVerificationFailed, 9008),
        (Error::HashingFailed, 9009),
        (Error::MissingAccounts, 9010),
        (Error::MissingSignature, 9011),
        (Error::ReadOnlyRegistry, 9012),
        (Error::InvalidSystemProgram, 9013),
        (Error::AlreadyInitialized, 9014),
        (Error::RevisionOverflow, 9015),
        (Error::UnsupportedBatch, 9016),
        (Error::NonCanonicalViewingKey, 9021),
        (Error::InvalidTrackingRegistry, 9022),
        (Error::InvalidTrackingAuthorization, 9023),
        (Error::EnrollmentAlreadyApplied, 9024),
        (Error::EnrollmentKeyFinal, 9025),
        (Error::ZeroNullifierKey, 9028),
        (Error::EnrollmentProofShape, 9029),
        (Error::NoEnrollmentsNamed, 9030),
        (Error::InvalidOwnerGrant, 9031),
        (Error::InvalidReaderKey, 9032),
        (Error::InvalidAuditorKey, 9033),
        (Error::InvalidAssetWrite, 9034),
        (Error::PrivateWriteWithoutRing, 9035),
        (Error::InvalidCredentialRead, 9036),
        (Error::InvalidPrivateRing, 9037),
    ];
    for (error, code) in pins {
        assert_eq!(error as u32, code, "{error:?}");
    }
    let fixture: BTreeMap<String, u32> = serde_json::from_str(include_str!(
        "../../../test-vectors/errors/storage-errors.json"
    ))
    .unwrap();
    let actual = pins
        .iter()
        .map(|(error, code)| (format!("{error:?}"), *code))
        .collect();
    assert_eq!(fixture, actual, "shared error code fixture drifted");
}
