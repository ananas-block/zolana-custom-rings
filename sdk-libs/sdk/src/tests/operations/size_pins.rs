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
    SizePin { n_in: 1, n_out: 2, bytes: [Some(1229), Some(1334), Some(1270), Some(1340), Some(1445), Some(1381), Some(1652), Some(1693), Some(1788), Some(1829), None] },
    SizePin { n_in: 1, n_out: 4, bytes: [Some(1565), Some(1734), Some(1606), Some(1676), Some(1845), Some(1717), Some(2338), Some(2379), Some(2474), Some(2515), None] },
    SizePin { n_in: 1, n_out: 8, bytes: [Some(2237), Some(2534), Some(2278), Some(2348), Some(2645), Some(2389), Some(3710), Some(3751), Some(3846), Some(3887), None] },
    SizePin { n_in: 2, n_out: 2, bytes: [Some(1294), Some(1399), Some(1335), Some(1421), Some(1526), Some(1462), Some(1733), Some(1774), Some(1925), Some(1966), Some(1367)] },
    SizePin { n_in: 2, n_out: 4, bytes: [Some(1630), Some(1799), Some(1671), Some(1757), Some(1926), Some(1798), Some(2419), Some(2460), Some(2611), Some(2652), None] },
    SizePin { n_in: 1, n_out: 16, bytes: [Some(3582), Some(4135), Some(3623), Some(3693), Some(4246), Some(3734), None, None, None, None, None] },
    SizePin { n_in: 2, n_out: 8, bytes: [Some(2302), Some(2599), Some(2343), Some(2429), Some(2726), Some(2470), Some(3791), Some(3832), Some(3983), Some(4024), None] },
    SizePin { n_in: 3, n_out: 2, bytes: [Some(1359), Some(1464), Some(1400), Some(1502), Some(1607), Some(1543), Some(1814), Some(1855), Some(2062), Some(2103), None] },
    SizePin { n_in: 3, n_out: 4, bytes: [Some(1695), Some(1864), Some(1736), Some(1838), Some(2007), Some(1879), Some(2500), Some(2541), Some(2748), Some(2789), None] },
    SizePin { n_in: 2, n_out: 16, bytes: [Some(3647), Some(4200), Some(3688), Some(3774), Some(4327), Some(3815), None, None, None, None, None] },
    SizePin { n_in: 3, n_out: 8, bytes: [Some(2367), Some(2664), Some(2408), Some(2510), Some(2807), Some(2551), Some(3872), Some(3913), None, None, None] },
    SizePin { n_in: 4, n_out: 2, bytes: [Some(1424), Some(1529), Some(1465), Some(1583), Some(1688), Some(1624), Some(1895), Some(1936), Some(2199), Some(2240), None] },
    SizePin { n_in: 4, n_out: 4, bytes: [Some(1760), Some(1929), Some(1801), Some(1919), Some(2088), Some(1960), Some(2581), Some(2622), Some(2885), Some(2926), Some(1865)] },
    SizePin { n_in: 4, n_out: 8, bytes: [Some(2432), Some(2729), Some(2473), Some(2591), Some(2888), Some(2632), Some(3953), Some(3994), None, None, None] },
    SizePin { n_in: 5, n_out: 2, bytes: [Some(1489), Some(1594), Some(1530), Some(1664), Some(1769), Some(1705), Some(1976), Some(2017), Some(2336), Some(2377), None] },
    SizePin { n_in: 5, n_out: 4, bytes: [Some(1825), Some(1994), Some(1866), Some(2000), Some(2169), Some(2041), Some(2662), Some(2703), Some(3022), Some(3063), None] },
    SizePin { n_in: 4, n_out: 16, bytes: [Some(3777), Some(4330), Some(3818), Some(3936), Some(4489), Some(3977), None, None, None, None, None] },
    SizePin { n_in: 5, n_out: 8, bytes: [Some(2497), Some(2794), Some(2538), Some(2672), Some(2969), Some(2713), Some(4034), Some(4075), None, None, None] },
    SizePin { n_in: 6, n_out: 2, bytes: [Some(1554), Some(1659), Some(1595), Some(1745), Some(1850), Some(1786), Some(2057), Some(2098), Some(2473), Some(2514), None] },
    SizePin { n_in: 6, n_out: 4, bytes: [Some(1890), Some(2059), Some(1931), Some(2081), Some(2250), Some(2122), Some(2743), Some(2784), Some(3159), Some(3200), None] },
    SizePin { n_in: 5, n_out: 16, bytes: [Some(3842), Some(4395), Some(3883), Some(4017), Some(4570), Some(4058), None, None, None, None, None] },
    SizePin { n_in: 6, n_out: 8, bytes: [Some(2562), Some(2859), Some(2603), Some(2753), Some(3050), Some(2794), None, None, None, None, None] },
    SizePin { n_in: 8, n_out: 2, bytes: [Some(1684), Some(1789), Some(1725), Some(1907), Some(2012), Some(1948), Some(2219), Some(2260), Some(2747), Some(2788), None] },
    SizePin { n_in: 8, n_out: 4, bytes: [Some(2020), Some(2189), Some(2061), Some(2243), Some(2412), Some(2284), Some(2905), Some(2946), Some(3433), Some(3474), None] },
    SizePin { n_in: 8, n_out: 8, bytes: [Some(2692), Some(2989), Some(2733), Some(2915), Some(3212), Some(2956), None, None, None, None, None] },
    SizePin { n_in: 8, n_out: 16, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 12, n_out: 2, bytes: [Some(1944), Some(2049), Some(1985), Some(2231), Some(2336), Some(2272), Some(2543), Some(2584), None, None, None] },
    SizePin { n_in: 12, n_out: 4, bytes: [Some(2280), Some(2449), Some(2321), Some(2567), Some(2736), Some(2608), Some(3229), Some(3270), None, None, None] },
    SizePin { n_in: 12, n_out: 8, bytes: [Some(2952), Some(3249), Some(2993), Some(3239), Some(3536), Some(3280), None, None, None, None, None] },
    SizePin { n_in: 16, n_out: 2, bytes: [Some(2204), Some(2309), Some(2245), Some(2555), Some(2660), Some(2596), Some(2867), Some(2908), None, None, None] },
    SizePin { n_in: 16, n_out: 4, bytes: [Some(2540), Some(2709), Some(2581), Some(2891), Some(3060), Some(2932), Some(3553), Some(3594), None, None, None] },
    SizePin { n_in: 16, n_out: 8, bytes: [Some(3212), Some(3509), Some(3253), Some(3563), Some(3860), Some(3604), None, None, None, None, None] },
    SizePin { n_in: 24, n_out: 2, bytes: [Some(2724), Some(2829), Some(2765), Some(3203), Some(3308), Some(3244), Some(3515), Some(3556), None, None, None] },
    SizePin { n_in: 24, n_out: 4, bytes: [Some(3060), Some(3229), Some(3101), Some(3539), Some(3708), Some(3580), None, None, None, None, None] },
    SizePin { n_in: 32, n_out: 2, bytes: [Some(3244), Some(3349), Some(3285), Some(3851), Some(3956), Some(3892), None, None, None, None, None] },
    SizePin { n_in: 40, n_out: 2, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 48, n_out: 2, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 49, n_out: 2, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
];
