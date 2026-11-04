// One table, included by the SDK size test and the validator sweep.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Measured {
    Confidential,
    ConfidentialPolicy,
    ConfidentialEscrow,
    InProofOwner,
    InProofOwnerPolicy,
    InProofOwnerEscrow,
    Anonymous,
    AnonymousPolicy,
    AnonymousEntry,
    AnonymousEntryPolicy,
    Delegate,
}

impl Measured {
    const COLUMNS: [Self; 11] = [
        Self::Confidential,
        Self::ConfidentialPolicy,
        Self::ConfidentialEscrow,
        Self::InProofOwner,
        Self::InProofOwnerPolicy,
        Self::InProofOwnerEscrow,
        Self::Anonymous,
        Self::AnonymousPolicy,
        Self::AnonymousEntry,
        Self::AnonymousEntryPolicy,
        Self::Delegate,
    ];
}

#[derive(Debug, PartialEq, Eq)]
struct SizePin {
    n_in: usize,
    n_out: usize,
    /// One per [`Measured::COLUMNS`] entry, `None` for a shape the rail has no key for.
    bytes: [Option<usize>; Measured::COLUMNS.len()],
}

/// A value past `MAX_TRANSACTION_SIZE` fails assembly.
#[rustfmt::skip]
const SIZE_PINS: [SizePin; 38] = [
    SizePin { n_in: 1, n_out: 2, bytes: [Some(1381), Some(1381), Some(1381), Some(1476), Some(1476), Some(1476), Some(1548), Some(1548), Some(1788), Some(1788), None] },
    SizePin { n_in: 1, n_out: 4, bytes: [Some(1815), Some(1815), Some(1815), Some(1910), Some(1910), Some(1910), Some(2046), Some(2046), Some(2286), Some(2286), None] },
    SizePin { n_in: 1, n_out: 8, bytes: [Some(2683), Some(2683), Some(2683), Some(2778), Some(2778), Some(2778), Some(3042), Some(3042), Some(3282), Some(3282), None] },
    SizePin { n_in: 2, n_out: 2, bytes: [Some(1446), Some(1446), Some(1446), Some(1541), Some(1541), Some(1541), Some(1613), Some(1613), Some(2053), Some(2053), Some(1405)] },
    SizePin { n_in: 2, n_out: 4, bytes: [Some(1880), Some(1880), Some(1880), Some(1975), Some(1975), Some(1975), Some(2111), Some(2111), Some(2551), Some(2551), None] },
    SizePin { n_in: 1, n_out: 16, bytes: [Some(4421), Some(4421), Some(4421), Some(4516), Some(4516), Some(4516), Some(5036), Some(5036), None, None, None] },
    SizePin { n_in: 2, n_out: 8, bytes: [Some(2748), Some(2748), Some(2748), Some(2843), Some(2843), Some(2843), Some(3107), Some(3107), Some(3547), Some(3547), None] },
    SizePin { n_in: 3, n_out: 2, bytes: [Some(1511), Some(1511), Some(1511), Some(1606), Some(1606), Some(1606), Some(1678), Some(1678), Some(2318), Some(2318), None] },
    SizePin { n_in: 3, n_out: 4, bytes: [Some(1945), Some(1945), Some(1945), Some(2040), Some(2040), Some(2040), Some(2176), Some(2176), Some(2816), Some(2816), None] },
    SizePin { n_in: 2, n_out: 16, bytes: [Some(4486), Some(4486), Some(4486), Some(4581), Some(4581), Some(4581), Some(5101), Some(5101), None, None, None] },
    SizePin { n_in: 3, n_out: 8, bytes: [Some(2813), Some(2813), Some(2813), Some(2908), Some(2908), Some(2908), Some(3172), Some(3172), None, None, None] },
    SizePin { n_in: 4, n_out: 2, bytes: [Some(1576), Some(1576), Some(1576), Some(1671), Some(1671), Some(1671), Some(1743), Some(1743), Some(2583), Some(2583), None] },
    SizePin { n_in: 4, n_out: 4, bytes: [Some(2010), Some(2010), Some(2010), Some(2105), Some(2105), Some(2105), Some(2241), Some(2241), Some(3081), Some(3081), Some(1969)] },
    SizePin { n_in: 4, n_out: 8, bytes: [Some(2878), Some(2878), Some(2878), Some(2973), Some(2973), Some(2973), Some(3237), Some(3237), None, None, None] },
    SizePin { n_in: 5, n_out: 2, bytes: [Some(1641), Some(1641), Some(1641), Some(1736), Some(1736), Some(1736), Some(1808), Some(1808), Some(2848), Some(2848), None] },
    SizePin { n_in: 5, n_out: 4, bytes: [Some(2075), Some(2075), Some(2075), Some(2170), Some(2170), Some(2170), Some(2306), Some(2306), Some(3346), Some(3346), None] },
    SizePin { n_in: 4, n_out: 16, bytes: [Some(4616), Some(4616), Some(4616), Some(4711), Some(4711), Some(4711), Some(5231), Some(5231), None, None, None] },
    SizePin { n_in: 5, n_out: 8, bytes: [Some(2943), Some(2943), Some(2943), Some(3038), Some(3038), Some(3038), Some(3302), Some(3302), None, None, None] },
    SizePin { n_in: 6, n_out: 2, bytes: [Some(1706), Some(1706), Some(1706), Some(1801), Some(1801), Some(1801), Some(1873), Some(1873), Some(3113), Some(3113), None] },
    SizePin { n_in: 6, n_out: 4, bytes: [Some(2140), Some(2140), Some(2140), Some(2235), Some(2235), Some(2235), Some(2371), Some(2371), Some(3611), Some(3611), None] },
    SizePin { n_in: 5, n_out: 16, bytes: [Some(4681), Some(4681), Some(4681), Some(4776), Some(4776), Some(4776), Some(5296), Some(5296), None, None, None] },
    SizePin { n_in: 6, n_out: 8, bytes: [Some(3008), Some(3008), Some(3008), Some(3103), Some(3103), Some(3103), Some(3367), Some(3367), None, None, None] },
    SizePin { n_in: 8, n_out: 2, bytes: [Some(1836), Some(1836), Some(1836), Some(1931), Some(1931), Some(1931), Some(2003), Some(2003), Some(3643), Some(3643), None] },
    SizePin { n_in: 8, n_out: 4, bytes: [Some(2270), Some(2270), Some(2270), Some(2365), Some(2365), Some(2365), Some(2501), Some(2501), Some(4141), Some(4141), None] },
    SizePin { n_in: 8, n_out: 8, bytes: [Some(3138), Some(3138), Some(3138), Some(3233), Some(3233), Some(3233), Some(3497), Some(3497), None, None, None] },
    SizePin { n_in: 8, n_out: 16, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 12, n_out: 2, bytes: [Some(2096), Some(2096), Some(2096), Some(2191), Some(2191), Some(2191), Some(2263), Some(2263), None, None, None] },
    SizePin { n_in: 12, n_out: 4, bytes: [Some(2530), Some(2530), Some(2530), Some(2625), Some(2625), Some(2625), Some(2761), Some(2761), None, None, None] },
    SizePin { n_in: 12, n_out: 8, bytes: [Some(3398), Some(3398), Some(3398), Some(3493), Some(3493), Some(3493), Some(3757), Some(3757), None, None, None] },
    SizePin { n_in: 16, n_out: 2, bytes: [Some(2356), Some(2356), Some(2356), Some(2451), Some(2451), Some(2451), Some(2523), Some(2523), None, None, None] },
    SizePin { n_in: 16, n_out: 4, bytes: [Some(2790), Some(2790), Some(2790), Some(2885), Some(2885), Some(2885), Some(3021), Some(3021), None, None, None] },
    SizePin { n_in: 16, n_out: 8, bytes: [Some(3658), Some(3658), Some(3658), Some(3753), Some(3753), Some(3753), Some(4017), Some(4017), None, None, None] },
    SizePin { n_in: 24, n_out: 2, bytes: [Some(2876), Some(2876), Some(2876), Some(2971), Some(2971), Some(2971), Some(3043), Some(3043), None, None, None] },
    SizePin { n_in: 24, n_out: 4, bytes: [Some(3310), Some(3310), Some(3310), Some(3405), Some(3405), Some(3405), Some(3541), Some(3541), None, None, None] },
    SizePin { n_in: 32, n_out: 2, bytes: [Some(3396), Some(3396), Some(3396), Some(3491), Some(3491), Some(3491), Some(3563), Some(3563), None, None, None] },
    SizePin { n_in: 40, n_out: 2, bytes: [Some(3916), Some(3916), Some(3916), Some(4011), Some(4011), Some(4011), Some(4083), Some(4083), None, None, None] },
    SizePin { n_in: 48, n_out: 2, bytes: [Some(4436), Some(4436), Some(4436), Some(4531), Some(4531), Some(4531), Some(4603), Some(4603), None, None, None] },
    SizePin { n_in: 49, n_out: 2, bytes: [Some(4501), Some(4501), Some(4501), Some(4596), Some(4596), Some(4596), Some(4668), Some(4668), None, None, None] },
];
