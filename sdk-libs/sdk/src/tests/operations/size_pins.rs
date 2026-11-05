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
    SizePin { n_in: 1, n_out: 2, bytes: [Some(1387), Some(1387), Some(1387), Some(1482), Some(1482), Some(1482), Some(1554), Some(1554), Some(1794), Some(1794), None] },
    SizePin { n_in: 1, n_out: 4, bytes: [Some(1821), Some(1821), Some(1821), Some(1916), Some(1916), Some(1916), Some(2052), Some(2052), Some(2292), Some(2292), None] },
    SizePin { n_in: 1, n_out: 8, bytes: [Some(2689), Some(2689), Some(2689), Some(2784), Some(2784), Some(2784), Some(3048), Some(3048), Some(3288), Some(3288), None] },
    SizePin { n_in: 2, n_out: 2, bytes: [Some(1452), Some(1452), Some(1452), Some(1547), Some(1547), Some(1547), Some(1619), Some(1619), Some(2059), Some(2059), Some(1411)] },
    SizePin { n_in: 2, n_out: 4, bytes: [Some(1886), Some(1886), Some(1886), Some(1981), Some(1981), Some(1981), Some(2117), Some(2117), Some(2557), Some(2557), None] },
    SizePin { n_in: 1, n_out: 16, bytes: [Some(4427), Some(4427), Some(4427), Some(4522), Some(4522), Some(4522), Some(5042), Some(5042), None, None, None] },
    SizePin { n_in: 2, n_out: 8, bytes: [Some(2754), Some(2754), Some(2754), Some(2849), Some(2849), Some(2849), Some(3113), Some(3113), Some(3553), Some(3553), None] },
    SizePin { n_in: 3, n_out: 2, bytes: [Some(1517), Some(1517), Some(1517), Some(1612), Some(1612), Some(1612), Some(1684), Some(1684), Some(2324), Some(2324), None] },
    SizePin { n_in: 3, n_out: 4, bytes: [Some(1951), Some(1951), Some(1951), Some(2046), Some(2046), Some(2046), Some(2182), Some(2182), Some(2822), Some(2822), None] },
    SizePin { n_in: 2, n_out: 16, bytes: [Some(4492), Some(4492), Some(4492), Some(4587), Some(4587), Some(4587), Some(5107), Some(5107), None, None, None] },
    SizePin { n_in: 3, n_out: 8, bytes: [Some(2819), Some(2819), Some(2819), Some(2914), Some(2914), Some(2914), Some(3178), Some(3178), Some(3818), Some(3818), None] },
    SizePin { n_in: 4, n_out: 2, bytes: [Some(1582), Some(1582), Some(1582), Some(1677), Some(1677), Some(1677), Some(1749), Some(1749), Some(2589), Some(2589), None] },
    SizePin { n_in: 4, n_out: 4, bytes: [Some(2016), Some(2016), Some(2016), Some(2111), Some(2111), Some(2111), Some(2247), Some(2247), Some(3087), Some(3087), Some(1975)] },
    SizePin { n_in: 4, n_out: 8, bytes: [Some(2884), Some(2884), Some(2884), Some(2979), Some(2979), Some(2979), Some(3243), Some(3243), Some(4083), Some(4083), None] },
    SizePin { n_in: 5, n_out: 2, bytes: [Some(1647), Some(1647), Some(1647), Some(1742), Some(1742), Some(1742), Some(1814), Some(1814), Some(2854), Some(2854), None] },
    SizePin { n_in: 5, n_out: 4, bytes: [Some(2081), Some(2081), Some(2081), Some(2176), Some(2176), Some(2176), Some(2312), Some(2312), Some(3352), Some(3352), None] },
    SizePin { n_in: 4, n_out: 16, bytes: [Some(4622), Some(4622), Some(4622), Some(4717), Some(4717), Some(4717), Some(5237), Some(5237), None, None, None] },
    SizePin { n_in: 5, n_out: 8, bytes: [Some(2949), Some(2949), Some(2949), Some(3044), Some(3044), Some(3044), Some(3308), Some(3308), None, None, None] },
    SizePin { n_in: 6, n_out: 2, bytes: [Some(1712), Some(1712), Some(1712), Some(1807), Some(1807), Some(1807), Some(1879), Some(1879), Some(3119), Some(3119), None] },
    SizePin { n_in: 6, n_out: 4, bytes: [Some(2146), Some(2146), Some(2146), Some(2241), Some(2241), Some(2241), Some(2377), Some(2377), Some(3617), Some(3617), None] },
    SizePin { n_in: 5, n_out: 16, bytes: [Some(4687), Some(4687), Some(4687), Some(4782), Some(4782), Some(4782), Some(5302), Some(5302), None, None, None] },
    SizePin { n_in: 6, n_out: 8, bytes: [Some(3014), Some(3014), Some(3014), Some(3109), Some(3109), Some(3109), Some(3373), Some(3373), None, None, None] },
    SizePin { n_in: 8, n_out: 2, bytes: [Some(1842), Some(1842), Some(1842), Some(1937), Some(1937), Some(1937), Some(2009), Some(2009), Some(3649), Some(3649), None] },
    SizePin { n_in: 8, n_out: 4, bytes: [Some(2276), Some(2276), Some(2276), Some(2371), Some(2371), Some(2371), Some(2507), Some(2507), Some(4147), Some(4147), None] },
    SizePin { n_in: 8, n_out: 8, bytes: [Some(3144), Some(3144), Some(3144), Some(3239), Some(3239), Some(3239), Some(3503), Some(3503), None, None, None] },
    SizePin { n_in: 8, n_out: 16, bytes: [Some(4882), Some(4882), Some(4882), Some(4977), Some(4977), Some(4977), Some(5497), Some(5497), None, None, None] },
    SizePin { n_in: 12, n_out: 2, bytes: [Some(2102), Some(2102), Some(2102), Some(2197), Some(2197), Some(2197), Some(2269), Some(2269), Some(4709), Some(4709), None] },
    SizePin { n_in: 12, n_out: 4, bytes: [Some(2536), Some(2536), Some(2536), Some(2631), Some(2631), Some(2631), Some(2767), Some(2767), None, None, None] },
    SizePin { n_in: 12, n_out: 8, bytes: [Some(3404), Some(3404), Some(3404), Some(3499), Some(3499), Some(3499), Some(3763), Some(3763), None, None, None] },
    SizePin { n_in: 16, n_out: 2, bytes: [Some(2362), Some(2362), Some(2362), Some(2457), Some(2457), Some(2457), Some(2529), Some(2529), Some(5769), Some(5769), None] },
    SizePin { n_in: 16, n_out: 4, bytes: [Some(2796), Some(2796), Some(2796), Some(2891), Some(2891), Some(2891), Some(3027), Some(3027), None, None, None] },
    SizePin { n_in: 16, n_out: 8, bytes: [Some(3664), Some(3664), Some(3664), Some(3759), Some(3759), Some(3759), Some(4023), Some(4023), None, None, None] },
    SizePin { n_in: 24, n_out: 2, bytes: [Some(2882), Some(2882), Some(2882), Some(2977), Some(2977), Some(2977), Some(3049), Some(3049), Some(7889), Some(7889), None] },
    SizePin { n_in: 24, n_out: 4, bytes: [Some(3316), Some(3316), Some(3316), Some(3411), Some(3411), Some(3411), Some(3547), Some(3547), None, None, None] },
    SizePin { n_in: 32, n_out: 2, bytes: [Some(3402), Some(3402), Some(3402), Some(3497), Some(3497), Some(3497), Some(3569), Some(3569), None, None, None] },
    SizePin { n_in: 40, n_out: 2, bytes: [Some(3922), Some(3922), Some(3922), Some(4017), Some(4017), Some(4017), Some(4089), Some(4089), None, None, None] },
    SizePin { n_in: 48, n_out: 2, bytes: [Some(4442), Some(4442), Some(4442), Some(4537), Some(4537), Some(4537), Some(4609), Some(4609), None, None, None] },
    SizePin { n_in: 49, n_out: 2, bytes: [Some(4507), Some(4507), Some(4507), Some(4602), Some(4602), Some(4602), Some(4674), Some(4674), None, None, None] },
];
