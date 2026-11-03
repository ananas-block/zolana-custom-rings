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
    SizePin { n_in: 1, n_out: 2, bytes: [Some(1262), Some(1367), Some(1303), Some(1357), Some(1462), Some(1398), Some(1615), Some(1615), Some(1783), Some(1783), None] },
    SizePin { n_in: 1, n_out: 4, bytes: [Some(1598), Some(1767), Some(1639), Some(1693), Some(1862), Some(1734), Some(2159), Some(2159), Some(2327), Some(2327), None] },
    SizePin { n_in: 1, n_out: 8, bytes: [Some(2270), Some(2567), Some(2311), Some(2365), Some(2662), Some(2406), Some(3247), Some(3247), Some(3415), Some(3415), None] },
    SizePin { n_in: 2, n_out: 2, bytes: [Some(1359), Some(1464), Some(1400), Some(1454), Some(1559), Some(1495), Some(1712), Some(1712), Some(1952), Some(1952), Some(1400)] },
    SizePin { n_in: 2, n_out: 4, bytes: [Some(1695), Some(1864), Some(1736), Some(1790), Some(1959), Some(1831), Some(2256), Some(2256), Some(2496), Some(2496), None] },
    SizePin { n_in: 1, n_out: 16, bytes: [Some(3615), Some(4168), Some(3656), Some(3710), Some(4263), Some(3751), None, None, None, None, None] },
    SizePin { n_in: 2, n_out: 8, bytes: [Some(2367), Some(2664), Some(2408), Some(2462), Some(2759), Some(2503), Some(3344), Some(3344), Some(3584), Some(3584), None] },
    SizePin { n_in: 3, n_out: 2, bytes: [Some(1456), Some(1561), Some(1497), Some(1551), Some(1656), Some(1592), Some(1809), Some(1809), Some(2121), Some(2121), None] },
    SizePin { n_in: 3, n_out: 4, bytes: [Some(1792), Some(1961), Some(1833), Some(1887), Some(2056), Some(1928), Some(2353), Some(2353), Some(2665), Some(2665), None] },
    SizePin { n_in: 2, n_out: 16, bytes: [Some(3712), Some(4265), Some(3753), Some(3807), Some(4360), Some(3848), None, None, None, None, None] },
    SizePin { n_in: 3, n_out: 8, bytes: [Some(2464), Some(2761), Some(2505), Some(2559), Some(2856), Some(2600), Some(3441), Some(3441), None, None, None] },
    SizePin { n_in: 4, n_out: 2, bytes: [Some(1553), Some(1658), Some(1594), Some(1648), Some(1753), Some(1689), Some(1906), Some(1906), Some(2290), Some(2290), None] },
    SizePin { n_in: 4, n_out: 4, bytes: [Some(1889), Some(2058), Some(1930), Some(1984), Some(2153), Some(2025), Some(2450), Some(2450), Some(2834), Some(2834), Some(1930)] },
    SizePin { n_in: 4, n_out: 8, bytes: [Some(2561), Some(2858), Some(2602), Some(2656), Some(2953), Some(2697), Some(3538), Some(3538), None, None, None] },
    SizePin { n_in: 5, n_out: 2, bytes: [Some(1650), Some(1755), Some(1691), Some(1745), Some(1850), Some(1786), Some(2003), Some(2003), Some(2459), Some(2459), None] },
    SizePin { n_in: 5, n_out: 4, bytes: [Some(1986), Some(2155), Some(2027), Some(2081), Some(2250), Some(2122), Some(2547), Some(2547), Some(3003), Some(3003), None] },
    SizePin { n_in: 4, n_out: 16, bytes: [Some(3906), Some(4459), Some(3947), Some(4001), Some(4554), Some(4042), None, None, None, None, None] },
    SizePin { n_in: 5, n_out: 8, bytes: [Some(2658), Some(2955), Some(2699), Some(2753), Some(3050), Some(2794), Some(3635), Some(3635), None, None, None] },
    SizePin { n_in: 6, n_out: 2, bytes: [Some(1747), Some(1852), Some(1788), Some(1842), Some(1947), Some(1883), Some(2100), Some(2100), Some(2628), Some(2628), None] },
    SizePin { n_in: 6, n_out: 4, bytes: [Some(2083), Some(2252), Some(2124), Some(2178), Some(2347), Some(2219), Some(2644), Some(2644), Some(3172), Some(3172), None] },
    SizePin { n_in: 5, n_out: 16, bytes: [Some(4003), Some(4556), Some(4044), Some(4098), Some(4651), Some(4139), None, None, None, None, None] },
    SizePin { n_in: 6, n_out: 8, bytes: [Some(2755), Some(3052), Some(2796), Some(2850), Some(3147), Some(2891), None, None, None, None, None] },
    SizePin { n_in: 8, n_out: 2, bytes: [Some(1941), Some(2046), Some(1982), Some(2036), Some(2141), Some(2077), Some(2294), Some(2294), Some(2966), Some(2966), None] },
    SizePin { n_in: 8, n_out: 4, bytes: [Some(2277), Some(2446), Some(2318), Some(2372), Some(2541), Some(2413), Some(2838), Some(2838), Some(3510), Some(3510), None] },
    SizePin { n_in: 8, n_out: 8, bytes: [Some(2949), Some(3246), Some(2990), Some(3044), Some(3341), Some(3085), None, None, None, None, None] },
    SizePin { n_in: 8, n_out: 16, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 12, n_out: 2, bytes: [Some(2329), Some(2434), Some(2370), Some(2424), Some(2529), Some(2465), Some(2682), Some(2682), None, None, None] },
    SizePin { n_in: 12, n_out: 4, bytes: [Some(2665), Some(2834), Some(2706), Some(2760), Some(2929), Some(2801), Some(3226), Some(3226), None, None, None] },
    SizePin { n_in: 12, n_out: 8, bytes: [Some(3337), Some(3634), Some(3378), Some(3432), Some(3729), Some(3473), None, None, None, None, None] },
    SizePin { n_in: 16, n_out: 2, bytes: [Some(2717), Some(2822), Some(2758), Some(2812), Some(2917), Some(2853), Some(3070), Some(3070), None, None, None] },
    SizePin { n_in: 16, n_out: 4, bytes: [Some(3053), Some(3222), Some(3094), Some(3148), Some(3317), Some(3189), Some(3614), Some(3614), None, None, None] },
    SizePin { n_in: 16, n_out: 8, bytes: [Some(3725), Some(4022), Some(3766), Some(3820), Some(4117), Some(3861), None, None, None, None, None] },
    SizePin { n_in: 24, n_out: 2, bytes: [Some(3493), Some(3598), Some(3534), Some(3588), Some(3693), Some(3629), Some(3846), Some(3846), None, None, None] },
    SizePin { n_in: 24, n_out: 4, bytes: [Some(3829), Some(3998), Some(3870), Some(3924), Some(4093), Some(3965), None, None, None, None, None] },
    SizePin { n_in: 32, n_out: 2, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 40, n_out: 2, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 48, n_out: 2, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 49, n_out: 2, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
];
