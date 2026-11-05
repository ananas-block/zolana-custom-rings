Measured with the frame encoders, SPP's account builders and the v1 compiler. Ceilings 4096 B, 64 accounts, 12 signatures.
min: one credential state tree, no co-signer, no leg, no fee, the payer an owner where it may be. full: own and curator roots, two credential state trees, one co-signer, 4 SOL legs, a fee, an outside payer, a body on every slot and one exit. Shared loads start credential state trees at tree zero and reuse the first SPP input tree as the address tree. Both full+4credential loads carry four credential state trees and two SPP input trees. The disjoint load uses separate address, credential state and SPP input trees. Full deposits use one credential state tree per slot. Ring-authority merges read one credential state tree. Owner-signed merges read none. The inline owner run is the inline ceilings' bound under full, the key's rows bound it apart. A shape's every input and output slot is published.
fits: the path that clears the transaction and CPI ceilings and the selected key credential capacity. limit: what stops a row with no path, rail for a shape the rail has no SPP key for, else the excess in credential trees, accounts, signatures, bytes, buffer create or CPI data at that row's load. A missing catalog key has no encoded measurement.
| shape | rail | load | catalog key | inline bytes | inline accounts | signatures | inline owner run | inline over | frame | SPP CPI | buffered bytes | buffered accounts | fits | limit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1x2 | confidential signer | min | yes | 1314 | 8 | 1 | - |  | 929 | 945 | 452 | 9 | inline |  |
| 1x2 | confidential signer | full | yes | 1904 | 19 | 3 | 1 |  | 1018 | 990 | 953 | 20 | inline |  |
| 1x2 | confidential signer | full+spl | yes | 2272 | 26 | 3 | - |  | 1150 | 994 | 1189 | 27 | inline |  |
| 1x2 | confidential signer | full+data | yes | 2104 | 19 | 3 | - |  | 1218 | 1186 | 953 | 20 | inline |  |
| 1x2 | confidential signer | full+reply | yes | 1904 | 19 | 3 | - |  | 1018 | 990 | 953 | 20 | inline |  |
| 1x2 | confidential signer | full+2tree | yes | 1910 | 19 | 3 | - |  | 1023 | 994 | 954 | 20 | inline |  |
| 1x2 | confidential signer | full+4credential-shared | yes | 1980 | 21 | 3 | - |  | 1027 | 994 | 1020 | 22 | inline |  |
| 1x2 | confidential signer | full+4credential-disjoint | yes | 2076 | 24 | 3 | - |  | 1027 | 994 | 1116 | 25 | inline |  |
| 1x2 | confidential in-proof | min | yes | 1409 | 8 | 1 | - |  | 1025 | 1042 | 451 | 9 | inline |  |
| 1x2 | confidential in-proof | full | yes | 1903 | 18 | 2 | 1 |  | 1114 | 1087 | 856 | 19 | inline |  |
| 1x2 | confidential in-proof | full+spl | yes | 2271 | 25 | 2 | - |  | 1246 | 1091 | 1092 | 26 | inline |  |
| 1x2 | confidential in-proof | full+data | yes | 2103 | 18 | 2 | - |  | 1314 | 1283 | 856 | 19 | inline |  |
| 1x2 | confidential in-proof | full+reply | yes | 1903 | 18 | 2 | - |  | 1114 | 1087 | 856 | 19 | inline |  |
| 1x2 | confidential in-proof | full+2tree | yes | 1909 | 18 | 2 | - |  | 1119 | 1091 | 857 | 19 | inline |  |
| 1x2 | confidential in-proof | full+4credential-shared | yes | 1979 | 20 | 2 | - |  | 1123 | 1091 | 923 | 21 | inline |  |
| 1x2 | confidential in-proof | full+4credential-disjoint | yes | 2075 | 23 | 2 | - |  | 1123 | 1091 | 1019 | 24 | inline |  |
| 1x2 | anonymous hidden | min | yes | 1481 | 8 | 1 | - |  | 1097 | 1144 | 451 | 9 | inline |  |
| 1x2 | anonymous hidden | full | yes | 1951 | 15 | 2 | 1 |  | 1258 | 1271 | 760 | 16 | inline |  |
| 1x2 | anonymous hidden | full+spl | yes | 2319 | 22 | 2 | - |  | 1390 | 1275 | 996 | 23 | inline |  |
| 1x2 | anonymous hidden | full+data | yes | 2151 | 15 | 2 | - |  | 1458 | 1467 | 760 | 16 | inline |  |
| 1x2 | anonymous hidden | full+reply | yes | 2050 | 15 | 2 | - |  | 1357 | 1368 | 760 | 16 | inline |  |
| 1x2 | anonymous hidden | full+2tree | yes | 1957 | 15 | 2 | - |  | 1263 | 1275 | 761 | 16 | inline |  |
| 1x2 | anonymous hidden | full+4credential-shared | yes | 2027 | 17 | 2 | - |  | 1267 | 1275 | 827 | 18 | inline |  |
| 1x2 | anonymous hidden | full+4credential-disjoint | yes | 2123 | 20 | 2 | - |  | 1267 | 1275 | 923 | 21 | inline |  |
| 1x2 | anonymous public owners | min | yes | 1418 | 8 | 1 | - |  | 1033 | 1047 | 452 | 9 | inline |  |
| 1x2 | anonymous public owners | full | yes | 2080 | 19 | 3 | 1 |  | 1194 | 1174 | 953 | 20 | inline |  |
| 1x2 | anonymous public owners | full+spl | yes | 2448 | 26 | 3 | - |  | 1326 | 1178 | 1189 | 27 | inline |  |
| 1x2 | anonymous public owners | full+data | yes | 2280 | 19 | 3 | - |  | 1394 | 1370 | 953 | 20 | inline |  |
| 1x2 | anonymous public owners | full+reply | yes | 2179 | 19 | 3 | - |  | 1293 | 1271 | 953 | 20 | inline |  |
| 1x2 | anonymous public owners | full+2tree | yes | 2086 | 19 | 3 | - |  | 1199 | 1178 | 954 | 20 | inline |  |
| 1x2 | anonymous public owners | full+4credential-shared | yes | 2156 | 21 | 3 | - |  | 1203 | 1178 | 1020 | 22 | inline |  |
| 1x2 | anonymous public owners | full+4credential-disjoint | yes | 2252 | 24 | 3 | - |  | 1203 | 1178 | 1116 | 25 | inline |  |
| 1x2 | confidential entry | min | yes | 1522 | 8 | 1 | - |  | 1137 | 1153 | 452 | 9 | inline |  |
| 1x2 | confidential entry | full | yes | 2112 | 19 | 3 | 1 |  | 1226 | 1198 | 953 | 20 | inline |  |
| 1x2 | confidential entry | full+spl | yes | 2480 | 26 | 3 | - |  | 1358 | 1202 | 1189 | 27 | inline |  |
| 1x2 | confidential entry | full+data | yes | 2312 | 19 | 3 | - |  | 1426 | 1394 | 953 | 20 | inline |  |
| 1x2 | confidential entry | full+reply | yes | 2112 | 19 | 3 | - |  | 1226 | 1198 | 953 | 20 | inline |  |
| 1x2 | confidential entry | full+2tree | yes | 2118 | 19 | 3 | - |  | 1231 | 1202 | 954 | 20 | inline |  |
| 1x2 | confidential entry | full+4credential-shared | yes | 2188 | 21 | 3 | - |  | 1235 | 1202 | 1020 | 22 | inline |  |
| 1x2 | confidential entry | full+4credential-disjoint | yes | 2284 | 24 | 3 | - |  | 1235 | 1202 | 1116 | 25 | inline |  |
| 1x2 | anonymous entry | min | yes | 1721 | 8 | 1 | - |  | 1337 | 1352 | 451 | 9 | inline |  |
| 1x2 | anonymous entry | full | yes | 2191 | 15 | 2 | 1 |  | 1498 | 1479 | 760 | 16 | inline |  |
| 1x2 | anonymous entry | full+spl | yes | 2559 | 22 | 2 | - |  | 1630 | 1483 | 996 | 23 | inline |  |
| 1x2 | anonymous entry | full+data | yes | 2391 | 15 | 2 | - |  | 1698 | 1675 | 760 | 16 | inline |  |
| 1x2 | anonymous entry | full+reply | yes | 2290 | 15 | 2 | - |  | 1597 | 1576 | 760 | 16 | inline |  |
| 1x2 | anonymous entry | full+2tree | yes | 2197 | 15 | 2 | - |  | 1503 | 1483 | 761 | 16 | inline |  |
| 1x2 | anonymous entry | full+4credential-shared | yes | 2267 | 17 | 2 | - |  | 1507 | 1483 | 827 | 18 | inline |  |
| 1x2 | anonymous entry | full+4credential-disjoint | yes | 2363 | 20 | 2 | - |  | 1507 | 1483 | 923 | 21 | inline |  |
| 1x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x4 | confidential signer | min | yes | 1748 | 8 | 1 | - |  | 1363 | 1451 | 452 | 9 | inline |  |
| 1x4 | confidential signer | full | yes | 2338 | 19 | 3 | 1 |  | 1452 | 1496 | 953 | 20 | inline |  |
| 1x4 | confidential signer | full+spl | yes | 2706 | 26 | 3 | - |  | 1584 | 1500 | 1189 | 27 | inline |  |
| 1x4 | confidential signer | full+data | yes | 2736 | 19 | 3 | - |  | 1850 | 1886 | 953 | 20 | inline |  |
| 1x4 | confidential signer | full+reply | yes | 2338 | 19 | 3 | - |  | 1452 | 1496 | 953 | 20 | inline |  |
| 1x4 | confidential signer | full+2tree | yes | 2344 | 19 | 3 | - |  | 1457 | 1500 | 954 | 20 | inline |  |
| 1x4 | confidential signer | full+4credential-shared | yes | 2414 | 21 | 3 | - |  | 1461 | 1500 | 1020 | 22 | inline |  |
| 1x4 | confidential signer | full+4credential-disjoint | yes | 2510 | 24 | 3 | - |  | 1461 | 1500 | 1116 | 25 | inline |  |
| 1x4 | confidential in-proof | min | yes | 1843 | 8 | 1 | - |  | 1459 | 1548 | 451 | 9 | inline |  |
| 1x4 | confidential in-proof | full | yes | 2337 | 18 | 2 | 1 |  | 1548 | 1593 | 856 | 19 | inline |  |
| 1x4 | confidential in-proof | full+spl | yes | 2705 | 25 | 2 | - |  | 1680 | 1597 | 1092 | 26 | inline |  |
| 1x4 | confidential in-proof | full+data | yes | 2735 | 18 | 2 | - |  | 1946 | 1983 | 856 | 19 | inline |  |
| 1x4 | confidential in-proof | full+reply | yes | 2337 | 18 | 2 | - |  | 1548 | 1593 | 856 | 19 | inline |  |
| 1x4 | confidential in-proof | full+2tree | yes | 2343 | 18 | 2 | - |  | 1553 | 1597 | 857 | 19 | inline |  |
| 1x4 | confidential in-proof | full+4credential-shared | yes | 2413 | 20 | 2 | - |  | 1557 | 1597 | 923 | 21 | inline |  |
| 1x4 | confidential in-proof | full+4credential-disjoint | yes | 2509 | 23 | 2 | - |  | 1557 | 1597 | 1019 | 24 | inline |  |
| 1x4 | anonymous hidden | min | yes | 1979 | 8 | 1 | - |  | 1595 | 1714 | 451 | 9 | inline |  |
| 1x4 | anonymous hidden | full | yes | 2449 | 15 | 2 | 1 |  | 1756 | 1841 | 760 | 16 | inline |  |
| 1x4 | anonymous hidden | full+spl | yes | 2817 | 22 | 2 | - |  | 1888 | 1845 | 996 | 23 | inline |  |
| 1x4 | anonymous hidden | full+data | yes | 2847 | 15 | 2 | - |  | 2154 | 2231 | 760 | 16 | inline |  |
| 1x4 | anonymous hidden | full+reply | yes | 2742 | 15 | 2 | - |  | 2049 | 2132 | 760 | 16 | inline |  |
| 1x4 | anonymous hidden | full+2tree | yes | 2455 | 15 | 2 | - |  | 1761 | 1845 | 761 | 16 | inline |  |
| 1x4 | anonymous hidden | full+4credential-shared | yes | 2525 | 17 | 2 | - |  | 1765 | 1845 | 827 | 18 | inline |  |
| 1x4 | anonymous hidden | full+4credential-disjoint | yes | 2621 | 20 | 2 | - |  | 1765 | 1845 | 923 | 21 | inline |  |
| 1x4 | anonymous public owners | min | yes | 1916 | 8 | 1 | - |  | 1531 | 1617 | 452 | 9 | inline |  |
| 1x4 | anonymous public owners | full | yes | 2578 | 19 | 3 | 1 |  | 1692 | 1744 | 953 | 20 | inline |  |
| 1x4 | anonymous public owners | full+spl | yes | 2946 | 26 | 3 | - |  | 1824 | 1748 | 1189 | 27 | inline |  |
| 1x4 | anonymous public owners | full+data | yes | 2976 | 19 | 3 | - |  | 2090 | 2134 | 953 | 20 | inline |  |
| 1x4 | anonymous public owners | full+reply | yes | 2871 | 19 | 3 | - |  | 1985 | 2035 | 953 | 20 | inline |  |
| 1x4 | anonymous public owners | full+2tree | yes | 2584 | 19 | 3 | - |  | 1697 | 1748 | 954 | 20 | inline |  |
| 1x4 | anonymous public owners | full+4credential-shared | yes | 2654 | 21 | 3 | - |  | 1701 | 1748 | 1020 | 22 | inline |  |
| 1x4 | anonymous public owners | full+4credential-disjoint | yes | 2750 | 24 | 3 | - |  | 1701 | 1748 | 1116 | 25 | inline |  |
| 1x4 | confidential entry | min | yes | 1956 | 8 | 1 | - |  | 1571 | 1659 | 452 | 9 | inline |  |
| 1x4 | confidential entry | full | yes | 2546 | 19 | 3 | 1 |  | 1660 | 1704 | 953 | 20 | inline |  |
| 1x4 | confidential entry | full+spl | yes | 2914 | 26 | 3 | - |  | 1792 | 1708 | 1189 | 27 | inline |  |
| 1x4 | confidential entry | full+data | yes | 2944 | 19 | 3 | - |  | 2058 | 2094 | 953 | 20 | inline |  |
| 1x4 | confidential entry | full+reply | yes | 2546 | 19 | 3 | - |  | 1660 | 1704 | 953 | 20 | inline |  |
| 1x4 | confidential entry | full+2tree | yes | 2552 | 19 | 3 | - |  | 1665 | 1708 | 954 | 20 | inline |  |
| 1x4 | confidential entry | full+4credential-shared | yes | 2622 | 21 | 3 | - |  | 1669 | 1708 | 1020 | 22 | inline |  |
| 1x4 | confidential entry | full+4credential-disjoint | yes | 2718 | 24 | 3 | - |  | 1669 | 1708 | 1116 | 25 | inline |  |
| 1x4 | anonymous entry | min | yes | 2219 | 8 | 1 | - |  | 1835 | 1922 | 451 | 9 | inline |  |
| 1x4 | anonymous entry | full | yes | 2689 | 15 | 2 | 1 |  | 1996 | 2049 | 760 | 16 | inline |  |
| 1x4 | anonymous entry | full+spl | yes | 3057 | 22 | 2 | - |  | 2128 | 2053 | 996 | 23 | inline |  |
| 1x4 | anonymous entry | full+data | yes | 3087 | 15 | 2 | - |  | 2394 | 2439 | 760 | 16 | inline |  |
| 1x4 | anonymous entry | full+reply | yes | 2982 | 15 | 2 | - |  | 2289 | 2340 | 760 | 16 | inline |  |
| 1x4 | anonymous entry | full+2tree | yes | 2695 | 15 | 2 | - |  | 2001 | 2053 | 761 | 16 | inline |  |
| 1x4 | anonymous entry | full+4credential-shared | yes | 2765 | 17 | 2 | - |  | 2005 | 2053 | 827 | 18 | inline |  |
| 1x4 | anonymous entry | full+4credential-disjoint | yes | 2861 | 20 | 2 | - |  | 2005 | 2053 | 923 | 21 | inline |  |
| 1x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x8 | confidential signer | min | yes | 2616 | 8 | 1 | - |  | 2231 | 2463 | 452 | 9 | inline |  |
| 1x8 | confidential signer | full | yes | 3206 | 19 | 3 | 1 |  | 2320 | 2508 | 953 | 20 | inline |  |
| 1x8 | confidential signer | full+spl | yes | 3574 | 26 | 3 | - |  | 2452 | 2512 | 1189 | 27 | inline |  |
| 1x8 | confidential signer | full+data | yes | 4000 | 19 | 3 | - |  | 3114 | 3286 | 953 | 20 | inline |  |
| 1x8 | confidential signer | full+reply | yes | 3206 | 19 | 3 | - |  | 2320 | 2508 | 953 | 20 | inline |  |
| 1x8 | confidential signer | full+2tree | yes | 3212 | 19 | 3 | - |  | 2325 | 2512 | 954 | 20 | inline |  |
| 1x8 | confidential signer | full+4credential-shared | yes | 3282 | 21 | 3 | - |  | 2329 | 2512 | 1020 | 22 | inline |  |
| 1x8 | confidential signer | full+4credential-disjoint | yes | 3378 | 24 | 3 | - |  | 2329 | 2512 | 1116 | 25 | inline |  |
| 1x8 | confidential in-proof | min | yes | 2711 | 8 | 1 | - |  | 2327 | 2560 | 451 | 9 | inline |  |
| 1x8 | confidential in-proof | full | yes | 3205 | 18 | 2 | 1 |  | 2416 | 2605 | 856 | 19 | inline |  |
| 1x8 | confidential in-proof | full+spl | yes | 3573 | 25 | 2 | - |  | 2548 | 2609 | 1092 | 26 | inline |  |
| 1x8 | confidential in-proof | full+data | yes | 3999 | 18 | 2 | - |  | 3210 | 3383 | 856 | 19 | inline |  |
| 1x8 | confidential in-proof | full+reply | yes | 3205 | 18 | 2 | - |  | 2416 | 2605 | 856 | 19 | inline |  |
| 1x8 | confidential in-proof | full+2tree | yes | 3211 | 18 | 2 | - |  | 2421 | 2609 | 857 | 19 | inline |  |
| 1x8 | confidential in-proof | full+4credential-shared | yes | 3281 | 20 | 2 | - |  | 2425 | 2609 | 923 | 21 | inline |  |
| 1x8 | confidential in-proof | full+4credential-disjoint | yes | 3377 | 23 | 2 | - |  | 2425 | 2609 | 1019 | 24 | inline |  |
| 1x8 | anonymous hidden | min | yes | 2975 | 8 | 1 | - |  | 2591 | 2854 | 451 | 9 | inline |  |
| 1x8 | anonymous hidden | full | yes | 3445 | 15 | 2 | 1 |  | 2752 | 2981 | 760 | 16 | inline |  |
| 1x8 | anonymous hidden | full+spl | yes | 3813 | 22 | 2 | - |  | 2884 | 2985 | 996 | 23 | inline |  |
| 1x8 | anonymous hidden | full+data | yes | 4239 | 15 | 2 | - | 143 B | 3546 | 3759 | 760 | 16 | buffered |  |
| 1x8 | anonymous hidden | full+reply | yes | 4126 | 15 | 2 | - | 30 B | 3433 | 3660 | 760 | 16 | buffered |  |
| 1x8 | anonymous hidden | full+2tree | yes | 3451 | 15 | 2 | - |  | 2757 | 2985 | 761 | 16 | inline |  |
| 1x8 | anonymous hidden | full+4credential-shared | yes | 3521 | 17 | 2 | - |  | 2761 | 2985 | 827 | 18 | inline |  |
| 1x8 | anonymous hidden | full+4credential-disjoint | yes | 3617 | 20 | 2 | - |  | 2761 | 2985 | 923 | 21 | inline |  |
| 1x8 | anonymous public owners | min | yes | 2912 | 8 | 1 | - |  | 2527 | 2757 | 452 | 9 | inline |  |
| 1x8 | anonymous public owners | full | yes | 3574 | 19 | 3 | 1 |  | 2688 | 2884 | 953 | 20 | inline |  |
| 1x8 | anonymous public owners | full+spl | yes | 3942 | 26 | 3 | - |  | 2820 | 2888 | 1189 | 27 | inline |  |
| 1x8 | anonymous public owners | full+data | yes | 4368 | 19 | 3 | - | 272 B | 3482 | 3662 | 953 | 20 | buffered |  |
| 1x8 | anonymous public owners | full+reply | yes | 4255 | 19 | 3 | - | 159 B | 3369 | 3563 | 953 | 20 | buffered |  |
| 1x8 | anonymous public owners | full+2tree | yes | 3580 | 19 | 3 | - |  | 2693 | 2888 | 954 | 20 | inline |  |
| 1x8 | anonymous public owners | full+4credential-shared | yes | 3650 | 21 | 3 | - |  | 2697 | 2888 | 1020 | 22 | inline |  |
| 1x8 | anonymous public owners | full+4credential-disjoint | yes | 3746 | 24 | 3 | - |  | 2697 | 2888 | 1116 | 25 | inline |  |
| 1x8 | confidential entry | min | yes | 2824 | 8 | 1 | - |  | 2439 | 2671 | 452 | 9 | inline |  |
| 1x8 | confidential entry | full | yes | 3414 | 19 | 3 | 1 |  | 2528 | 2716 | 953 | 20 | inline |  |
| 1x8 | confidential entry | full+spl | yes | 3782 | 26 | 3 | - |  | 2660 | 2720 | 1189 | 27 | inline |  |
| 1x8 | confidential entry | full+data | yes | 4208 | 19 | 3 | - | 112 B | 3322 | 3494 | 953 | 20 | buffered |  |
| 1x8 | confidential entry | full+reply | yes | 3414 | 19 | 3 | - |  | 2528 | 2716 | 953 | 20 | inline |  |
| 1x8 | confidential entry | full+2tree | yes | 3420 | 19 | 3 | - |  | 2533 | 2720 | 954 | 20 | inline |  |
| 1x8 | confidential entry | full+4credential-shared | yes | 3490 | 21 | 3 | - |  | 2537 | 2720 | 1020 | 22 | inline |  |
| 1x8 | confidential entry | full+4credential-disjoint | yes | 3586 | 24 | 3 | - |  | 2537 | 2720 | 1116 | 25 | inline |  |
| 1x8 | anonymous entry | min | yes | 3215 | 8 | 1 | - |  | 2831 | 3062 | 451 | 9 | inline |  |
| 1x8 | anonymous entry | full | yes | 3685 | 15 | 2 | 1 |  | 2992 | 3189 | 760 | 16 | inline |  |
| 1x8 | anonymous entry | full+spl | yes | 4053 | 22 | 2 | - |  | 3124 | 3193 | 996 | 23 | inline |  |
| 1x8 | anonymous entry | full+data | yes | 4479 | 15 | 2 | - | 383 B | 3786 | 3967 | 760 | 16 | buffered |  |
| 1x8 | anonymous entry | full+reply | yes | 4366 | 15 | 2 | - | 270 B | 3673 | 3868 | 760 | 16 | buffered |  |
| 1x8 | anonymous entry | full+2tree | yes | 3691 | 15 | 2 | - |  | 2997 | 3193 | 761 | 16 | inline |  |
| 1x8 | anonymous entry | full+4credential-shared | yes | 3761 | 17 | 2 | - |  | 3001 | 3193 | 827 | 18 | inline |  |
| 1x8 | anonymous entry | full+4credential-disjoint | yes | 3857 | 20 | 2 | - |  | 3001 | 3193 | 923 | 21 | inline |  |
| 1x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 2x2 | confidential signer | min | yes | 1379 | 9 | 1 | - |  | 961 | 978 | 485 | 10 | inline |  |
| 2x2 | confidential signer | full | yes | 1969 | 20 | 3 | 2 |  | 1050 | 1023 | 986 | 21 | inline |  |
| 2x2 | confidential signer | full+spl | yes | 2337 | 27 | 3 | - |  | 1182 | 1027 | 1222 | 28 | inline |  |
| 2x2 | confidential signer | full+data | yes | 2169 | 20 | 3 | - |  | 1250 | 1219 | 986 | 21 | inline |  |
| 2x2 | confidential signer | full+reply | yes | 1969 | 20 | 3 | - |  | 1050 | 1023 | 986 | 21 | inline |  |
| 2x2 | confidential signer | full+2tree | yes | 1975 | 20 | 3 | - |  | 1055 | 1027 | 987 | 21 | inline |  |
| 2x2 | confidential signer | full+4credential-shared | yes | 2045 | 22 | 3 | - |  | 1059 | 1027 | 1053 | 23 | inline |  |
| 2x2 | confidential signer | full+4credential-disjoint | yes | 2141 | 25 | 3 | - |  | 1059 | 1027 | 1149 | 26 | inline |  |
| 2x2 | confidential in-proof | min | yes | 1474 | 9 | 1 | - |  | 1057 | 1075 | 484 | 10 | inline |  |
| 2x2 | confidential in-proof | full | yes | 1968 | 19 | 2 | 2 |  | 1146 | 1120 | 889 | 20 | inline |  |
| 2x2 | confidential in-proof | full+spl | yes | 2336 | 26 | 2 | - |  | 1278 | 1124 | 1125 | 27 | inline |  |
| 2x2 | confidential in-proof | full+data | yes | 2168 | 19 | 2 | - |  | 1346 | 1316 | 889 | 20 | inline |  |
| 2x2 | confidential in-proof | full+reply | yes | 1968 | 19 | 2 | - |  | 1146 | 1120 | 889 | 20 | inline |  |
| 2x2 | confidential in-proof | full+2tree | yes | 1974 | 19 | 2 | - |  | 1151 | 1124 | 890 | 20 | inline |  |
| 2x2 | confidential in-proof | full+4credential-shared | yes | 2044 | 21 | 2 | - |  | 1155 | 1124 | 956 | 22 | inline |  |
| 2x2 | confidential in-proof | full+4credential-disjoint | yes | 2140 | 24 | 2 | - |  | 1155 | 1124 | 1052 | 25 | inline |  |
| 2x2 | anonymous hidden | min | yes | 1546 | 9 | 1 | - |  | 1129 | 1177 | 484 | 10 | inline |  |
| 2x2 | anonymous hidden | full | yes | 2016 | 16 | 2 | 2 |  | 1290 | 1304 | 793 | 17 | inline |  |
| 2x2 | anonymous hidden | full+spl | yes | 2384 | 23 | 2 | - |  | 1422 | 1308 | 1029 | 24 | inline |  |
| 2x2 | anonymous hidden | full+data | yes | 2216 | 16 | 2 | - |  | 1490 | 1500 | 793 | 17 | inline |  |
| 2x2 | anonymous hidden | full+reply | yes | 2115 | 16 | 2 | - |  | 1389 | 1401 | 793 | 17 | inline |  |
| 2x2 | anonymous hidden | full+2tree | yes | 2022 | 16 | 2 | - |  | 1295 | 1308 | 794 | 17 | inline |  |
| 2x2 | anonymous hidden | full+4credential-shared | yes | 2092 | 18 | 2 | - |  | 1299 | 1308 | 860 | 19 | inline |  |
| 2x2 | anonymous hidden | full+4credential-disjoint | yes | 2188 | 21 | 2 | - |  | 1299 | 1308 | 956 | 22 | inline |  |
| 2x2 | anonymous public owners | min | yes | 1483 | 9 | 1 | - |  | 1065 | 1080 | 485 | 10 | inline |  |
| 2x2 | anonymous public owners | full | yes | 2145 | 20 | 3 | 2 |  | 1226 | 1207 | 986 | 21 | inline |  |
| 2x2 | anonymous public owners | full+spl | yes | 2513 | 27 | 3 | - |  | 1358 | 1211 | 1222 | 28 | inline |  |
| 2x2 | anonymous public owners | full+data | yes | 2345 | 20 | 3 | - |  | 1426 | 1403 | 986 | 21 | inline |  |
| 2x2 | anonymous public owners | full+reply | yes | 2244 | 20 | 3 | - |  | 1325 | 1304 | 986 | 21 | inline |  |
| 2x2 | anonymous public owners | full+2tree | yes | 2151 | 20 | 3 | - |  | 1231 | 1211 | 987 | 21 | inline |  |
| 2x2 | anonymous public owners | full+4credential-shared | yes | 2221 | 22 | 3 | - |  | 1235 | 1211 | 1053 | 23 | inline |  |
| 2x2 | anonymous public owners | full+4credential-disjoint | yes | 2317 | 25 | 3 | - |  | 1235 | 1211 | 1149 | 26 | inline |  |
| 2x2 | confidential entry | min | yes | 1787 | 9 | 1 | - |  | 1369 | 1386 | 485 | 10 | inline |  |
| 2x2 | confidential entry | full | yes | 2377 | 20 | 3 | 2 |  | 1458 | 1431 | 986 | 21 | inline |  |
| 2x2 | confidential entry | full+spl | yes | 2745 | 27 | 3 | - |  | 1590 | 1435 | 1222 | 28 | inline |  |
| 2x2 | confidential entry | full+data | yes | 2577 | 20 | 3 | - |  | 1658 | 1627 | 986 | 21 | inline |  |
| 2x2 | confidential entry | full+reply | yes | 2377 | 20 | 3 | - |  | 1458 | 1431 | 986 | 21 | inline |  |
| 2x2 | confidential entry | full+2tree | yes | 2383 | 20 | 3 | - |  | 1463 | 1435 | 987 | 21 | inline |  |
| 2x2 | confidential entry | full+4credential-shared | yes | 2453 | 22 | 3 | - |  | 1467 | 1435 | 1053 | 23 | inline |  |
| 2x2 | confidential entry | full+4credential-disjoint | yes | 2549 | 25 | 3 | - |  | 1467 | 1435 | 1149 | 26 | inline |  |
| 2x2 | anonymous entry | min | yes | 1986 | 9 | 1 | - |  | 1569 | 1585 | 484 | 10 | inline |  |
| 2x2 | anonymous entry | full | yes | 2456 | 16 | 2 | 2 |  | 1730 | 1712 | 793 | 17 | inline |  |
| 2x2 | anonymous entry | full+spl | yes | 2824 | 23 | 2 | - |  | 1862 | 1716 | 1029 | 24 | inline |  |
| 2x2 | anonymous entry | full+data | yes | 2656 | 16 | 2 | - |  | 1930 | 1908 | 793 | 17 | inline |  |
| 2x2 | anonymous entry | full+reply | yes | 2555 | 16 | 2 | - |  | 1829 | 1809 | 793 | 17 | inline |  |
| 2x2 | anonymous entry | full+2tree | yes | 2462 | 16 | 2 | - |  | 1735 | 1716 | 794 | 17 | inline |  |
| 2x2 | anonymous entry | full+4credential-shared | yes | 2532 | 18 | 2 | - |  | 1739 | 1716 | 860 | 19 | inline |  |
| 2x2 | anonymous entry | full+4credential-disjoint | yes | 2628 | 21 | 2 | - |  | 1739 | 1716 | 956 | 22 | inline |  |
| 2x2 | delegate | min | yes | 1379 | 9 | 1 | - |  | 961 | 978 | 485 | 10 | inline |  |
| 2x2 | delegate | full | yes | 1757 | 16 | 2 | - |  | 1034 | 1023 | 790 | 17 | inline |  |
| 2x2 | delegate | full+spl | yes | 1997 | 23 | 2 | - |  | 1038 | 1027 | 1026 | 24 | inline |  |
| 2x2 | delegate | full+data | yes | 1957 | 16 | 2 | - |  | 1234 | 1219 | 790 | 17 | inline |  |
| 2x2 | delegate | full+reply | yes | 1757 | 16 | 2 | - |  | 1034 | 1023 | 790 | 17 | inline |  |
| 2x2 | delegate | full+2tree | yes | 1763 | 16 | 2 | - |  | 1039 | 1027 | 791 | 17 | inline |  |
| 2x2 | delegate | full+4credential-shared | yes | 1833 | 18 | 2 | - |  | 1043 | 1027 | 857 | 19 | inline |  |
| 2x2 | delegate | full+4credential-disjoint | yes | 1929 | 21 | 2 | - |  | 1043 | 1027 | 953 | 22 | inline |  |
| 2x2 | anonymous delegate | min | yes | 1483 | 9 | 1 | - |  | 1065 | 1080 | 485 | 10 | inline |  |
| 2x2 | anonymous delegate | full | yes | 1933 | 16 | 2 | - |  | 1210 | 1207 | 790 | 17 | inline |  |
| 2x2 | anonymous delegate | full+spl | yes | 2173 | 23 | 2 | - |  | 1214 | 1211 | 1026 | 24 | inline |  |
| 2x2 | anonymous delegate | full+data | yes | 2133 | 16 | 2 | - |  | 1410 | 1403 | 790 | 17 | inline |  |
| 2x2 | anonymous delegate | full+reply | yes | 2032 | 16 | 2 | - |  | 1309 | 1304 | 790 | 17 | inline |  |
| 2x2 | anonymous delegate | full+2tree | yes | 1939 | 16 | 2 | - |  | 1215 | 1211 | 791 | 17 | inline |  |
| 2x2 | anonymous delegate | full+4credential-shared | yes | 2009 | 18 | 2 | - |  | 1219 | 1211 | 857 | 19 | inline |  |
| 2x2 | anonymous delegate | full+4credential-disjoint | yes | 2105 | 21 | 2 | - |  | 1219 | 1211 | 953 | 22 | inline |  |
| 2x4 | confidential signer | min | yes | 1813 | 9 | 1 | - |  | 1395 | 1484 | 485 | 10 | inline |  |
| 2x4 | confidential signer | full | yes | 2403 | 20 | 3 | 2 |  | 1484 | 1529 | 986 | 21 | inline |  |
| 2x4 | confidential signer | full+spl | yes | 2771 | 27 | 3 | - |  | 1616 | 1533 | 1222 | 28 | inline |  |
| 2x4 | confidential signer | full+data | yes | 2801 | 20 | 3 | - |  | 1882 | 1919 | 986 | 21 | inline |  |
| 2x4 | confidential signer | full+reply | yes | 2403 | 20 | 3 | - |  | 1484 | 1529 | 986 | 21 | inline |  |
| 2x4 | confidential signer | full+2tree | yes | 2409 | 20 | 3 | - |  | 1489 | 1533 | 987 | 21 | inline |  |
| 2x4 | confidential signer | full+4credential-shared | yes | 2479 | 22 | 3 | - |  | 1493 | 1533 | 1053 | 23 | inline |  |
| 2x4 | confidential signer | full+4credential-disjoint | yes | 2575 | 25 | 3 | - |  | 1493 | 1533 | 1149 | 26 | inline |  |
| 2x4 | confidential in-proof | min | yes | 1908 | 9 | 1 | - |  | 1491 | 1581 | 484 | 10 | inline |  |
| 2x4 | confidential in-proof | full | yes | 2402 | 19 | 2 | 2 |  | 1580 | 1626 | 889 | 20 | inline |  |
| 2x4 | confidential in-proof | full+spl | yes | 2770 | 26 | 2 | - |  | 1712 | 1630 | 1125 | 27 | inline |  |
| 2x4 | confidential in-proof | full+data | yes | 2800 | 19 | 2 | - |  | 1978 | 2016 | 889 | 20 | inline |  |
| 2x4 | confidential in-proof | full+reply | yes | 2402 | 19 | 2 | - |  | 1580 | 1626 | 889 | 20 | inline |  |
| 2x4 | confidential in-proof | full+2tree | yes | 2408 | 19 | 2 | - |  | 1585 | 1630 | 890 | 20 | inline |  |
| 2x4 | confidential in-proof | full+4credential-shared | yes | 2478 | 21 | 2 | - |  | 1589 | 1630 | 956 | 22 | inline |  |
| 2x4 | confidential in-proof | full+4credential-disjoint | yes | 2574 | 24 | 2 | - |  | 1589 | 1630 | 1052 | 25 | inline |  |
| 2x4 | anonymous hidden | min | yes | 2044 | 9 | 1 | - |  | 1627 | 1747 | 484 | 10 | inline |  |
| 2x4 | anonymous hidden | full | yes | 2514 | 16 | 2 | 2 |  | 1788 | 1874 | 793 | 17 | inline |  |
| 2x4 | anonymous hidden | full+spl | yes | 2882 | 23 | 2 | - |  | 1920 | 1878 | 1029 | 24 | inline |  |
| 2x4 | anonymous hidden | full+data | yes | 2912 | 16 | 2 | - |  | 2186 | 2264 | 793 | 17 | inline |  |
| 2x4 | anonymous hidden | full+reply | yes | 2807 | 16 | 2 | - |  | 2081 | 2165 | 793 | 17 | inline |  |
| 2x4 | anonymous hidden | full+2tree | yes | 2520 | 16 | 2 | - |  | 1793 | 1878 | 794 | 17 | inline |  |
| 2x4 | anonymous hidden | full+4credential-shared | yes | 2590 | 18 | 2 | - |  | 1797 | 1878 | 860 | 19 | inline |  |
| 2x4 | anonymous hidden | full+4credential-disjoint | yes | 2686 | 21 | 2 | - |  | 1797 | 1878 | 956 | 22 | inline |  |
| 2x4 | anonymous public owners | min | yes | 1981 | 9 | 1 | - |  | 1563 | 1650 | 485 | 10 | inline |  |
| 2x4 | anonymous public owners | full | yes | 2643 | 20 | 3 | 2 |  | 1724 | 1777 | 986 | 21 | inline |  |
| 2x4 | anonymous public owners | full+spl | yes | 3011 | 27 | 3 | - |  | 1856 | 1781 | 1222 | 28 | inline |  |
| 2x4 | anonymous public owners | full+data | yes | 3041 | 20 | 3 | - |  | 2122 | 2167 | 986 | 21 | inline |  |
| 2x4 | anonymous public owners | full+reply | yes | 2936 | 20 | 3 | - |  | 2017 | 2068 | 986 | 21 | inline |  |
| 2x4 | anonymous public owners | full+2tree | yes | 2649 | 20 | 3 | - |  | 1729 | 1781 | 987 | 21 | inline |  |
| 2x4 | anonymous public owners | full+4credential-shared | yes | 2719 | 22 | 3 | - |  | 1733 | 1781 | 1053 | 23 | inline |  |
| 2x4 | anonymous public owners | full+4credential-disjoint | yes | 2815 | 25 | 3 | - |  | 1733 | 1781 | 1149 | 26 | inline |  |
| 2x4 | confidential entry | min | yes | 2221 | 9 | 1 | - |  | 1803 | 1892 | 485 | 10 | inline |  |
| 2x4 | confidential entry | full | yes | 2811 | 20 | 3 | 2 |  | 1892 | 1937 | 986 | 21 | inline |  |
| 2x4 | confidential entry | full+spl | yes | 3179 | 27 | 3 | - |  | 2024 | 1941 | 1222 | 28 | inline |  |
| 2x4 | confidential entry | full+data | yes | 3209 | 20 | 3 | - |  | 2290 | 2327 | 986 | 21 | inline |  |
| 2x4 | confidential entry | full+reply | yes | 2811 | 20 | 3 | - |  | 1892 | 1937 | 986 | 21 | inline |  |
| 2x4 | confidential entry | full+2tree | yes | 2817 | 20 | 3 | - |  | 1897 | 1941 | 987 | 21 | inline |  |
| 2x4 | confidential entry | full+4credential-shared | yes | 2887 | 22 | 3 | - |  | 1901 | 1941 | 1053 | 23 | inline |  |
| 2x4 | confidential entry | full+4credential-disjoint | yes | 2983 | 25 | 3 | - |  | 1901 | 1941 | 1149 | 26 | inline |  |
| 2x4 | anonymous entry | min | yes | 2484 | 9 | 1 | - |  | 2067 | 2155 | 484 | 10 | inline |  |
| 2x4 | anonymous entry | full | yes | 2954 | 16 | 2 | 2 |  | 2228 | 2282 | 793 | 17 | inline |  |
| 2x4 | anonymous entry | full+spl | yes | 3322 | 23 | 2 | - |  | 2360 | 2286 | 1029 | 24 | inline |  |
| 2x4 | anonymous entry | full+data | yes | 3352 | 16 | 2 | - |  | 2626 | 2672 | 793 | 17 | inline |  |
| 2x4 | anonymous entry | full+reply | yes | 3247 | 16 | 2 | - |  | 2521 | 2573 | 793 | 17 | inline |  |
| 2x4 | anonymous entry | full+2tree | yes | 2960 | 16 | 2 | - |  | 2233 | 2286 | 794 | 17 | inline |  |
| 2x4 | anonymous entry | full+4credential-shared | yes | 3030 | 18 | 2 | - |  | 2237 | 2286 | 860 | 19 | inline |  |
| 2x4 | anonymous entry | full+4credential-disjoint | yes | 3126 | 21 | 2 | - |  | 2237 | 2286 | 956 | 22 | inline |  |
| 2x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 2x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x16 | confidential signer | min | yes | 4354 | 8 | 1 | - | 258 B | 3969 | 4487 | 452 | 9 | buffered |  |
| 1x16 | confidential signer | full | yes | 4944 | 19 | 3 | none | 848 B | 4058 | 4532 | 953 | 20 | buffered |  |
| 1x16 | confidential signer | full+spl | yes | 5312 | 26 | 3 | - | 1216 B | 4190 | 4536 | 1189 | 27 | buffered |  |
| 1x16 | confidential signer | full+data | yes | 6530 | 19 | 3 | - | 2434 B | 5644 | 6086 | 953 | 20 | buffered |  |
| 1x16 | confidential signer | full+reply | yes | 4944 | 19 | 3 | - | 848 B | 4058 | 4532 | 953 | 20 | buffered |  |
| 1x16 | confidential signer | full+2tree | yes | 4950 | 19 | 3 | - | 854 B | 4063 | 4536 | 954 | 20 | buffered |  |
| 1x16 | confidential signer | full+4credential-shared | yes | 5020 | 21 | 3 | - | 924 B | 4067 | 4536 | 1020 | 22 | buffered |  |
| 1x16 | confidential signer | full+4credential-disjoint | yes | 5116 | 24 | 3 | - | 1020 B | 4067 | 4536 | 1116 | 25 | buffered |  |
| 1x16 | confidential in-proof | min | yes | 4449 | 8 | 1 | - | 353 B | 4065 | 4584 | 451 | 9 | buffered |  |
| 1x16 | confidential in-proof | full | yes | 4943 | 18 | 2 | none | 847 B | 4154 | 4629 | 856 | 19 | buffered |  |
| 1x16 | confidential in-proof | full+spl | yes | 5311 | 25 | 2 | - | 1215 B | 4286 | 4633 | 1092 | 26 | buffered |  |
| 1x16 | confidential in-proof | full+data | yes | 6529 | 18 | 2 | - | 2433 B | 5740 | 6183 | 856 | 19 | buffered |  |
| 1x16 | confidential in-proof | full+reply | yes | 4943 | 18 | 2 | - | 847 B | 4154 | 4629 | 856 | 19 | buffered |  |
| 1x16 | confidential in-proof | full+2tree | yes | 4949 | 18 | 2 | - | 853 B | 4159 | 4633 | 857 | 19 | buffered |  |
| 1x16 | confidential in-proof | full+4credential-shared | yes | 5019 | 20 | 2 | - | 923 B | 4163 | 4633 | 923 | 21 | buffered |  |
| 1x16 | confidential in-proof | full+4credential-disjoint | yes | 5115 | 23 | 2 | - | 1019 B | 4163 | 4633 | 1019 | 24 | buffered |  |
| 1x16 | anonymous hidden | min | yes | 4969 | 8 | 1 | - | 873 B | 4585 | 5134 | 451 | 9 | buffered |  |
| 1x16 | anonymous hidden | full | yes | 5439 | 15 | 2 | none | 1343 B | 4746 | 5261 | 760 | 16 | buffered |  |
| 1x16 | anonymous hidden | full+spl | yes | 5807 | 22 | 2 | - | 1711 B | 4878 | 5265 | 996 | 23 | buffered |  |
| 1x16 | anonymous hidden | full+data | yes | 7025 | 15 | 2 | - | 2929 B | 6332 | 6815 | 760 | 16 | buffered |  |
| 1x16 | anonymous hidden | full+reply | yes | 6896 | 15 | 2 | - | 2800 B | 6203 | 6716 | 760 | 16 | buffered |  |
| 1x16 | anonymous hidden | full+2tree | yes | 5445 | 15 | 2 | - | 1349 B | 4751 | 5265 | 761 | 16 | buffered |  |
| 1x16 | anonymous hidden | full+4credential-shared | yes | 5515 | 17 | 2 | - | 1419 B | 4755 | 5265 | 827 | 18 | buffered |  |
| 1x16 | anonymous hidden | full+4credential-disjoint | yes | 5611 | 20 | 2 | - | 1515 B | 4755 | 5265 | 923 | 21 | buffered |  |
| 1x16 | anonymous public owners | min | yes | 4906 | 8 | 1 | - | 810 B | 4521 | 5037 | 452 | 9 | buffered |  |
| 1x16 | anonymous public owners | full | yes | 5568 | 19 | 3 | none | 1472 B | 4682 | 5164 | 953 | 20 | buffered |  |
| 1x16 | anonymous public owners | full+spl | yes | 5936 | 26 | 3 | - | 1840 B | 4814 | 5168 | 1189 | 27 | buffered |  |
| 1x16 | anonymous public owners | full+data | yes | 7154 | 19 | 3 | - | 3058 B | 6268 | 6718 | 953 | 20 | buffered |  |
| 1x16 | anonymous public owners | full+reply | yes | 7025 | 19 | 3 | - | 2929 B | 6139 | 6619 | 953 | 20 | buffered |  |
| 1x16 | anonymous public owners | full+2tree | yes | 5574 | 19 | 3 | - | 1478 B | 4687 | 5168 | 954 | 20 | buffered |  |
| 1x16 | anonymous public owners | full+4credential-shared | yes | 5644 | 21 | 3 | - | 1548 B | 4691 | 5168 | 1020 | 22 | buffered |  |
| 1x16 | anonymous public owners | full+4credential-disjoint | yes | 5740 | 24 | 3 | - | 1644 B | 4691 | 5168 | 1116 | 25 | buffered |  |
| 1x16 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 1x16 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x16 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 2x8 | confidential signer | min | yes | 2681 | 9 | 1 | - |  | 2263 | 2496 | 485 | 10 | inline |  |
| 2x8 | confidential signer | full | yes | 3271 | 20 | 3 | 2 |  | 2352 | 2541 | 986 | 21 | inline |  |
| 2x8 | confidential signer | full+spl | yes | 3639 | 27 | 3 | - |  | 2484 | 2545 | 1222 | 28 | inline |  |
| 2x8 | confidential signer | full+data | yes | 4065 | 20 | 3 | - |  | 3146 | 3319 | 986 | 21 | inline |  |
| 2x8 | confidential signer | full+reply | yes | 3271 | 20 | 3 | - |  | 2352 | 2541 | 986 | 21 | inline |  |
| 2x8 | confidential signer | full+2tree | yes | 3277 | 20 | 3 | - |  | 2357 | 2545 | 987 | 21 | inline |  |
| 2x8 | confidential signer | full+4credential-shared | yes | 3347 | 22 | 3 | - |  | 2361 | 2545 | 1053 | 23 | inline |  |
| 2x8 | confidential signer | full+4credential-disjoint | yes | 3443 | 25 | 3 | - |  | 2361 | 2545 | 1149 | 26 | inline |  |
| 2x8 | confidential in-proof | min | yes | 2776 | 9 | 1 | - |  | 2359 | 2593 | 484 | 10 | inline |  |
| 2x8 | confidential in-proof | full | yes | 3270 | 19 | 2 | 2 |  | 2448 | 2638 | 889 | 20 | inline |  |
| 2x8 | confidential in-proof | full+spl | yes | 3638 | 26 | 2 | - |  | 2580 | 2642 | 1125 | 27 | inline |  |
| 2x8 | confidential in-proof | full+data | yes | 4064 | 19 | 2 | - |  | 3242 | 3416 | 889 | 20 | inline |  |
| 2x8 | confidential in-proof | full+reply | yes | 3270 | 19 | 2 | - |  | 2448 | 2638 | 889 | 20 | inline |  |
| 2x8 | confidential in-proof | full+2tree | yes | 3276 | 19 | 2 | - |  | 2453 | 2642 | 890 | 20 | inline |  |
| 2x8 | confidential in-proof | full+4credential-shared | yes | 3346 | 21 | 2 | - |  | 2457 | 2642 | 956 | 22 | inline |  |
| 2x8 | confidential in-proof | full+4credential-disjoint | yes | 3442 | 24 | 2 | - |  | 2457 | 2642 | 1052 | 25 | inline |  |
| 2x8 | anonymous hidden | min | yes | 3040 | 9 | 1 | - |  | 2623 | 2887 | 484 | 10 | inline |  |
| 2x8 | anonymous hidden | full | yes | 3510 | 16 | 2 | 2 |  | 2784 | 3014 | 793 | 17 | inline |  |
| 2x8 | anonymous hidden | full+spl | yes | 3878 | 23 | 2 | - |  | 2916 | 3018 | 1029 | 24 | inline |  |
| 2x8 | anonymous hidden | full+data | yes | 4304 | 16 | 2 | - | 208 B | 3578 | 3792 | 793 | 17 | buffered |  |
| 2x8 | anonymous hidden | full+reply | yes | 4191 | 16 | 2 | - | 95 B | 3465 | 3693 | 793 | 17 | buffered |  |
| 2x8 | anonymous hidden | full+2tree | yes | 3516 | 16 | 2 | - |  | 2789 | 3018 | 794 | 17 | inline |  |
| 2x8 | anonymous hidden | full+4credential-shared | yes | 3586 | 18 | 2 | - |  | 2793 | 3018 | 860 | 19 | inline |  |
| 2x8 | anonymous hidden | full+4credential-disjoint | yes | 3682 | 21 | 2 | - |  | 2793 | 3018 | 956 | 22 | inline |  |
| 2x8 | anonymous public owners | min | yes | 2977 | 9 | 1 | - |  | 2559 | 2790 | 485 | 10 | inline |  |
| 2x8 | anonymous public owners | full | yes | 3639 | 20 | 3 | 2 |  | 2720 | 2917 | 986 | 21 | inline |  |
| 2x8 | anonymous public owners | full+spl | yes | 4007 | 27 | 3 | - |  | 2852 | 2921 | 1222 | 28 | inline |  |
| 2x8 | anonymous public owners | full+data | yes | 4433 | 20 | 3 | - | 337 B | 3514 | 3695 | 986 | 21 | buffered |  |
| 2x8 | anonymous public owners | full+reply | yes | 4320 | 20 | 3 | - | 224 B | 3401 | 3596 | 986 | 21 | buffered |  |
| 2x8 | anonymous public owners | full+2tree | yes | 3645 | 20 | 3 | - |  | 2725 | 2921 | 987 | 21 | inline |  |
| 2x8 | anonymous public owners | full+4credential-shared | yes | 3715 | 22 | 3 | - |  | 2729 | 2921 | 1053 | 23 | inline |  |
| 2x8 | anonymous public owners | full+4credential-disjoint | yes | 3811 | 25 | 3 | - |  | 2729 | 2921 | 1149 | 26 | inline |  |
| 2x8 | confidential entry | min | yes | 3089 | 9 | 1 | - |  | 2671 | 2904 | 485 | 10 | inline |  |
| 2x8 | confidential entry | full | yes | 3679 | 20 | 3 | 2 |  | 2760 | 2949 | 986 | 21 | inline |  |
| 2x8 | confidential entry | full+spl | yes | 4047 | 27 | 3 | - |  | 2892 | 2953 | 1222 | 28 | inline |  |
| 2x8 | confidential entry | full+data | yes | 4473 | 20 | 3 | - | 377 B | 3554 | 3727 | 986 | 21 | buffered |  |
| 2x8 | confidential entry | full+reply | yes | 3679 | 20 | 3 | - |  | 2760 | 2949 | 986 | 21 | inline |  |
| 2x8 | confidential entry | full+2tree | yes | 3685 | 20 | 3 | - |  | 2765 | 2953 | 987 | 21 | inline |  |
| 2x8 | confidential entry | full+4credential-shared | yes | 3755 | 22 | 3 | - |  | 2769 | 2953 | 1053 | 23 | inline |  |
| 2x8 | confidential entry | full+4credential-disjoint | yes | 3851 | 25 | 3 | - |  | 2769 | 2953 | 1149 | 26 | inline |  |
| 2x8 | anonymous entry | min | yes | 3480 | 9 | 1 | - |  | 3063 | 3295 | 484 | 10 | inline |  |
| 2x8 | anonymous entry | full | yes | 3950 | 16 | 2 | 1 |  | 3224 | 3422 | 793 | 17 | inline |  |
| 2x8 | anonymous entry | full+spl | yes | 4318 | 23 | 2 | - | 222 B | 3356 | 3426 | 1029 | 24 | buffered |  |
| 2x8 | anonymous entry | full+data | yes | 4744 | 16 | 2 | - | 648 B | 4018 | 4200 | 793 | 17 | buffered |  |
| 2x8 | anonymous entry | full+reply | yes | 4631 | 16 | 2 | - | 535 B | 3905 | 4101 | 793 | 17 | buffered |  |
| 2x8 | anonymous entry | full+2tree | yes | 3956 | 16 | 2 | - |  | 3229 | 3426 | 794 | 17 | inline |  |
| 2x8 | anonymous entry | full+4credential-shared | yes | 4026 | 18 | 2 | - |  | 3233 | 3426 | 860 | 19 | inline |  |
| 2x8 | anonymous entry | full+4credential-disjoint | yes | 4122 | 21 | 2 | - | 26 B | 3233 | 3426 | 956 | 22 | buffered |  |
| 2x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 2x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 3x2 | confidential signer | min | yes | 1444 | 10 | 1 | - |  | 993 | 1011 | 518 | 11 | inline |  |
| 3x2 | confidential signer | full | yes | 2034 | 21 | 3 | 3 |  | 1082 | 1056 | 1019 | 22 | inline |  |
| 3x2 | confidential signer | full+spl | yes | 2402 | 28 | 3 | - |  | 1214 | 1060 | 1255 | 29 | inline |  |
| 3x2 | confidential signer | full+data | yes | 2234 | 21 | 3 | - |  | 1282 | 1252 | 1019 | 22 | inline |  |
| 3x2 | confidential signer | full+reply | yes | 2034 | 21 | 3 | - |  | 1082 | 1056 | 1019 | 22 | inline |  |
| 3x2 | confidential signer | full+2tree | yes | 2040 | 21 | 3 | - |  | 1087 | 1060 | 1020 | 22 | inline |  |
| 3x2 | confidential signer | full+4credential-shared | yes | 2110 | 23 | 3 | - |  | 1091 | 1060 | 1086 | 24 | inline |  |
| 3x2 | confidential signer | full+4credential-disjoint | yes | 2206 | 26 | 3 | - |  | 1091 | 1060 | 1182 | 27 | inline |  |
| 3x2 | confidential in-proof | min | yes | 1539 | 10 | 1 | - |  | 1089 | 1108 | 517 | 11 | inline |  |
| 3x2 | confidential in-proof | full | yes | 2033 | 20 | 2 | 3 |  | 1178 | 1153 | 922 | 21 | inline |  |
| 3x2 | confidential in-proof | full+spl | yes | 2401 | 27 | 2 | - |  | 1310 | 1157 | 1158 | 28 | inline |  |
| 3x2 | confidential in-proof | full+data | yes | 2233 | 20 | 2 | - |  | 1378 | 1349 | 922 | 21 | inline |  |
| 3x2 | confidential in-proof | full+reply | yes | 2033 | 20 | 2 | - |  | 1178 | 1153 | 922 | 21 | inline |  |
| 3x2 | confidential in-proof | full+2tree | yes | 2039 | 20 | 2 | - |  | 1183 | 1157 | 923 | 21 | inline |  |
| 3x2 | confidential in-proof | full+4credential-shared | yes | 2109 | 22 | 2 | - |  | 1187 | 1157 | 989 | 23 | inline |  |
| 3x2 | confidential in-proof | full+4credential-disjoint | yes | 2205 | 25 | 2 | - |  | 1187 | 1157 | 1085 | 26 | inline |  |
| 3x2 | anonymous hidden | min | yes | 1611 | 10 | 1 | - |  | 1161 | 1210 | 517 | 11 | inline |  |
| 3x2 | anonymous hidden | full | yes | 2081 | 17 | 2 | 3 |  | 1322 | 1337 | 826 | 18 | inline |  |
| 3x2 | anonymous hidden | full+spl | yes | 2449 | 24 | 2 | - |  | 1454 | 1341 | 1062 | 25 | inline |  |
| 3x2 | anonymous hidden | full+data | yes | 2281 | 17 | 2 | - |  | 1522 | 1533 | 826 | 18 | inline |  |
| 3x2 | anonymous hidden | full+reply | yes | 2180 | 17 | 2 | - |  | 1421 | 1434 | 826 | 18 | inline |  |
| 3x2 | anonymous hidden | full+2tree | yes | 2087 | 17 | 2 | - |  | 1327 | 1341 | 827 | 18 | inline |  |
| 3x2 | anonymous hidden | full+4credential-shared | yes | 2157 | 19 | 2 | - |  | 1331 | 1341 | 893 | 20 | inline |  |
| 3x2 | anonymous hidden | full+4credential-disjoint | yes | 2253 | 22 | 2 | - |  | 1331 | 1341 | 989 | 23 | inline |  |
| 3x2 | anonymous public owners | min | yes | 1548 | 10 | 1 | - |  | 1097 | 1113 | 518 | 11 | inline |  |
| 3x2 | anonymous public owners | full | yes | 2210 | 21 | 3 | 3 |  | 1258 | 1240 | 1019 | 22 | inline |  |
| 3x2 | anonymous public owners | full+spl | yes | 2578 | 28 | 3 | - |  | 1390 | 1244 | 1255 | 29 | inline |  |
| 3x2 | anonymous public owners | full+data | yes | 2410 | 21 | 3 | - |  | 1458 | 1436 | 1019 | 22 | inline |  |
| 3x2 | anonymous public owners | full+reply | yes | 2309 | 21 | 3 | - |  | 1357 | 1337 | 1019 | 22 | inline |  |
| 3x2 | anonymous public owners | full+2tree | yes | 2216 | 21 | 3 | - |  | 1263 | 1244 | 1020 | 22 | inline |  |
| 3x2 | anonymous public owners | full+4credential-shared | yes | 2286 | 23 | 3 | - |  | 1267 | 1244 | 1086 | 24 | inline |  |
| 3x2 | anonymous public owners | full+4credential-disjoint | yes | 2382 | 26 | 3 | - |  | 1267 | 1244 | 1182 | 27 | inline |  |
| 3x2 | confidential entry | min | yes | 2052 | 10 | 1 | - |  | 1601 | 1619 | 518 | 11 | inline |  |
| 3x2 | confidential entry | full | yes | 2642 | 21 | 3 | 3 |  | 1690 | 1664 | 1019 | 22 | inline |  |
| 3x2 | confidential entry | full+spl | yes | 3010 | 28 | 3 | - |  | 1822 | 1668 | 1255 | 29 | inline |  |
| 3x2 | confidential entry | full+data | yes | 2842 | 21 | 3 | - |  | 1890 | 1860 | 1019 | 22 | inline |  |
| 3x2 | confidential entry | full+reply | yes | 2642 | 21 | 3 | - |  | 1690 | 1664 | 1019 | 22 | inline |  |
| 3x2 | confidential entry | full+2tree | yes | 2648 | 21 | 3 | - |  | 1695 | 1668 | 1020 | 22 | inline |  |
| 3x2 | confidential entry | full+4credential-shared | yes | 2718 | 23 | 3 | - |  | 1699 | 1668 | 1086 | 24 | inline |  |
| 3x2 | confidential entry | full+4credential-disjoint | yes | 2814 | 26 | 3 | - |  | 1699 | 1668 | 1182 | 27 | inline |  |
| 3x2 | anonymous entry | min | yes | 2251 | 10 | 1 | - |  | 1801 | 1818 | 517 | 11 | inline |  |
| 3x2 | anonymous entry | full | yes | 2721 | 17 | 2 | 3 |  | 1962 | 1945 | 826 | 18 | inline |  |
| 3x2 | anonymous entry | full+spl | yes | 3089 | 24 | 2 | - |  | 2094 | 1949 | 1062 | 25 | inline |  |
| 3x2 | anonymous entry | full+data | yes | 2921 | 17 | 2 | - |  | 2162 | 2141 | 826 | 18 | inline |  |
| 3x2 | anonymous entry | full+reply | yes | 2820 | 17 | 2 | - |  | 2061 | 2042 | 826 | 18 | inline |  |
| 3x2 | anonymous entry | full+2tree | yes | 2727 | 17 | 2 | - |  | 1967 | 1949 | 827 | 18 | inline |  |
| 3x2 | anonymous entry | full+4credential-shared | yes | 2797 | 19 | 2 | - |  | 1971 | 1949 | 893 | 20 | inline |  |
| 3x2 | anonymous entry | full+4credential-disjoint | yes | 2893 | 22 | 2 | - |  | 1971 | 1949 | 989 | 23 | inline |  |
| 3x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 3x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 3x4 | confidential signer | min | yes | 1878 | 10 | 1 | - |  | 1427 | 1517 | 518 | 11 | inline |  |
| 3x4 | confidential signer | full | yes | 2468 | 21 | 3 | 3 |  | 1516 | 1562 | 1019 | 22 | inline |  |
| 3x4 | confidential signer | full+spl | yes | 2836 | 28 | 3 | - |  | 1648 | 1566 | 1255 | 29 | inline |  |
| 3x4 | confidential signer | full+data | yes | 2866 | 21 | 3 | - |  | 1914 | 1952 | 1019 | 22 | inline |  |
| 3x4 | confidential signer | full+reply | yes | 2468 | 21 | 3 | - |  | 1516 | 1562 | 1019 | 22 | inline |  |
| 3x4 | confidential signer | full+2tree | yes | 2474 | 21 | 3 | - |  | 1521 | 1566 | 1020 | 22 | inline |  |
| 3x4 | confidential signer | full+4credential-shared | yes | 2544 | 23 | 3 | - |  | 1525 | 1566 | 1086 | 24 | inline |  |
| 3x4 | confidential signer | full+4credential-disjoint | yes | 2640 | 26 | 3 | - |  | 1525 | 1566 | 1182 | 27 | inline |  |
| 3x4 | confidential in-proof | min | yes | 1973 | 10 | 1 | - |  | 1523 | 1614 | 517 | 11 | inline |  |
| 3x4 | confidential in-proof | full | yes | 2467 | 20 | 2 | 3 |  | 1612 | 1659 | 922 | 21 | inline |  |
| 3x4 | confidential in-proof | full+spl | yes | 2835 | 27 | 2 | - |  | 1744 | 1663 | 1158 | 28 | inline |  |
| 3x4 | confidential in-proof | full+data | yes | 2865 | 20 | 2 | - |  | 2010 | 2049 | 922 | 21 | inline |  |
| 3x4 | confidential in-proof | full+reply | yes | 2467 | 20 | 2 | - |  | 1612 | 1659 | 922 | 21 | inline |  |
| 3x4 | confidential in-proof | full+2tree | yes | 2473 | 20 | 2 | - |  | 1617 | 1663 | 923 | 21 | inline |  |
| 3x4 | confidential in-proof | full+4credential-shared | yes | 2543 | 22 | 2 | - |  | 1621 | 1663 | 989 | 23 | inline |  |
| 3x4 | confidential in-proof | full+4credential-disjoint | yes | 2639 | 25 | 2 | - |  | 1621 | 1663 | 1085 | 26 | inline |  |
| 3x4 | anonymous hidden | min | yes | 2109 | 10 | 1 | - |  | 1659 | 1780 | 517 | 11 | inline |  |
| 3x4 | anonymous hidden | full | yes | 2579 | 17 | 2 | 3 |  | 1820 | 1907 | 826 | 18 | inline |  |
| 3x4 | anonymous hidden | full+spl | yes | 2947 | 24 | 2 | - |  | 1952 | 1911 | 1062 | 25 | inline |  |
| 3x4 | anonymous hidden | full+data | yes | 2977 | 17 | 2 | - |  | 2218 | 2297 | 826 | 18 | inline |  |
| 3x4 | anonymous hidden | full+reply | yes | 2872 | 17 | 2 | - |  | 2113 | 2198 | 826 | 18 | inline |  |
| 3x4 | anonymous hidden | full+2tree | yes | 2585 | 17 | 2 | - |  | 1825 | 1911 | 827 | 18 | inline |  |
| 3x4 | anonymous hidden | full+4credential-shared | yes | 2655 | 19 | 2 | - |  | 1829 | 1911 | 893 | 20 | inline |  |
| 3x4 | anonymous hidden | full+4credential-disjoint | yes | 2751 | 22 | 2 | - |  | 1829 | 1911 | 989 | 23 | inline |  |
| 3x4 | anonymous public owners | min | yes | 2046 | 10 | 1 | - |  | 1595 | 1683 | 518 | 11 | inline |  |
| 3x4 | anonymous public owners | full | yes | 2708 | 21 | 3 | 3 |  | 1756 | 1810 | 1019 | 22 | inline |  |
| 3x4 | anonymous public owners | full+spl | yes | 3076 | 28 | 3 | - |  | 1888 | 1814 | 1255 | 29 | inline |  |
| 3x4 | anonymous public owners | full+data | yes | 3106 | 21 | 3 | - |  | 2154 | 2200 | 1019 | 22 | inline |  |
| 3x4 | anonymous public owners | full+reply | yes | 3001 | 21 | 3 | - |  | 2049 | 2101 | 1019 | 22 | inline |  |
| 3x4 | anonymous public owners | full+2tree | yes | 2714 | 21 | 3 | - |  | 1761 | 1814 | 1020 | 22 | inline |  |
| 3x4 | anonymous public owners | full+4credential-shared | yes | 2784 | 23 | 3 | - |  | 1765 | 1814 | 1086 | 24 | inline |  |
| 3x4 | anonymous public owners | full+4credential-disjoint | yes | 2880 | 26 | 3 | - |  | 1765 | 1814 | 1182 | 27 | inline |  |
| 3x4 | confidential entry | min | yes | 2486 | 10 | 1 | - |  | 2035 | 2125 | 518 | 11 | inline |  |
| 3x4 | confidential entry | full | yes | 3076 | 21 | 3 | 3 |  | 2124 | 2170 | 1019 | 22 | inline |  |
| 3x4 | confidential entry | full+spl | yes | 3444 | 28 | 3 | - |  | 2256 | 2174 | 1255 | 29 | inline |  |
| 3x4 | confidential entry | full+data | yes | 3474 | 21 | 3 | - |  | 2522 | 2560 | 1019 | 22 | inline |  |
| 3x4 | confidential entry | full+reply | yes | 3076 | 21 | 3 | - |  | 2124 | 2170 | 1019 | 22 | inline |  |
| 3x4 | confidential entry | full+2tree | yes | 3082 | 21 | 3 | - |  | 2129 | 2174 | 1020 | 22 | inline |  |
| 3x4 | confidential entry | full+4credential-shared | yes | 3152 | 23 | 3 | - |  | 2133 | 2174 | 1086 | 24 | inline |  |
| 3x4 | confidential entry | full+4credential-disjoint | yes | 3248 | 26 | 3 | - |  | 2133 | 2174 | 1182 | 27 | inline |  |
| 3x4 | anonymous entry | min | yes | 2749 | 10 | 1 | - |  | 2299 | 2388 | 517 | 11 | inline |  |
| 3x4 | anonymous entry | full | yes | 3219 | 17 | 2 | 3 |  | 2460 | 2515 | 826 | 18 | inline |  |
| 3x4 | anonymous entry | full+spl | yes | 3587 | 24 | 2 | - |  | 2592 | 2519 | 1062 | 25 | inline |  |
| 3x4 | anonymous entry | full+data | yes | 3617 | 17 | 2 | - |  | 2858 | 2905 | 826 | 18 | inline |  |
| 3x4 | anonymous entry | full+reply | yes | 3512 | 17 | 2 | - |  | 2753 | 2806 | 826 | 18 | inline |  |
| 3x4 | anonymous entry | full+2tree | yes | 3225 | 17 | 2 | - |  | 2465 | 2519 | 827 | 18 | inline |  |
| 3x4 | anonymous entry | full+4credential-shared | yes | 3295 | 19 | 2 | - |  | 2469 | 2519 | 893 | 20 | inline |  |
| 3x4 | anonymous entry | full+4credential-disjoint | yes | 3391 | 22 | 2 | - |  | 2469 | 2519 | 989 | 23 | inline |  |
| 3x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 3x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 2x16 | confidential signer | min | yes | 4419 | 9 | 1 | - | 323 B | 4001 | 4520 | 485 | 10 | buffered |  |
| 2x16 | confidential signer | full | yes | 5009 | 20 | 3 | none | 913 B | 4090 | 4565 | 986 | 21 | buffered |  |
| 2x16 | confidential signer | full+spl | yes | 5377 | 27 | 3 | - | 1281 B | 4222 | 4569 | 1222 | 28 | buffered |  |
| 2x16 | confidential signer | full+data | yes | 6595 | 20 | 3 | - | 2499 B | 5676 | 6119 | 986 | 21 | buffered |  |
| 2x16 | confidential signer | full+reply | yes | 5009 | 20 | 3 | - | 913 B | 4090 | 4565 | 986 | 21 | buffered |  |
| 2x16 | confidential signer | full+2tree | yes | 5015 | 20 | 3 | - | 919 B | 4095 | 4569 | 987 | 21 | buffered |  |
| 2x16 | confidential signer | full+4credential-shared | yes | 5085 | 22 | 3 | - | 989 B | 4099 | 4569 | 1053 | 23 | buffered |  |
| 2x16 | confidential signer | full+4credential-disjoint | yes | 5181 | 25 | 3 | - | 1085 B | 4099 | 4569 | 1149 | 26 | buffered |  |
| 2x16 | confidential in-proof | min | yes | 4514 | 9 | 1 | - | 418 B | 4097 | 4617 | 484 | 10 | buffered |  |
| 2x16 | confidential in-proof | full | yes | 5008 | 19 | 2 | none | 912 B | 4186 | 4662 | 889 | 20 | buffered |  |
| 2x16 | confidential in-proof | full+spl | yes | 5376 | 26 | 2 | - | 1280 B | 4318 | 4666 | 1125 | 27 | buffered |  |
| 2x16 | confidential in-proof | full+data | yes | 6594 | 19 | 2 | - | 2498 B | 5772 | 6216 | 889 | 20 | buffered |  |
| 2x16 | confidential in-proof | full+reply | yes | 5008 | 19 | 2 | - | 912 B | 4186 | 4662 | 889 | 20 | buffered |  |
| 2x16 | confidential in-proof | full+2tree | yes | 5014 | 19 | 2 | - | 918 B | 4191 | 4666 | 890 | 20 | buffered |  |
| 2x16 | confidential in-proof | full+4credential-shared | yes | 5084 | 21 | 2 | - | 988 B | 4195 | 4666 | 956 | 22 | buffered |  |
| 2x16 | confidential in-proof | full+4credential-disjoint | yes | 5180 | 24 | 2 | - | 1084 B | 4195 | 4666 | 1052 | 25 | buffered |  |
| 2x16 | anonymous hidden | min | yes | 5034 | 9 | 1 | - | 938 B | 4617 | 5167 | 484 | 10 | buffered |  |
| 2x16 | anonymous hidden | full | yes | 5504 | 16 | 2 | none | 1408 B | 4778 | 5294 | 793 | 17 | buffered |  |
| 2x16 | anonymous hidden | full+spl | yes | 5872 | 23 | 2 | - | 1776 B | 4910 | 5298 | 1029 | 24 | buffered |  |
| 2x16 | anonymous hidden | full+data | yes | 7090 | 16 | 2 | - | 2994 B | 6364 | 6848 | 793 | 17 | buffered |  |
| 2x16 | anonymous hidden | full+reply | yes | 6961 | 16 | 2 | - | 2865 B | 6235 | 6749 | 793 | 17 | buffered |  |
| 2x16 | anonymous hidden | full+2tree | yes | 5510 | 16 | 2 | - | 1414 B | 4783 | 5298 | 794 | 17 | buffered |  |
| 2x16 | anonymous hidden | full+4credential-shared | yes | 5580 | 18 | 2 | - | 1484 B | 4787 | 5298 | 860 | 19 | buffered |  |
| 2x16 | anonymous hidden | full+4credential-disjoint | yes | 5676 | 21 | 2 | - | 1580 B | 4787 | 5298 | 956 | 22 | buffered |  |
| 2x16 | anonymous public owners | min | yes | 4971 | 9 | 1 | - | 875 B | 4553 | 5070 | 485 | 10 | buffered |  |
| 2x16 | anonymous public owners | full | yes | 5633 | 20 | 3 | none | 1537 B | 4714 | 5197 | 986 | 21 | buffered |  |
| 2x16 | anonymous public owners | full+spl | yes | 6001 | 27 | 3 | - | 1905 B | 4846 | 5201 | 1222 | 28 | buffered |  |
| 2x16 | anonymous public owners | full+data | yes | 7219 | 20 | 3 | - | 3123 B | 6300 | 6751 | 986 | 21 | buffered |  |
| 2x16 | anonymous public owners | full+reply | yes | 7090 | 20 | 3 | - | 2994 B | 6171 | 6652 | 986 | 21 | buffered |  |
| 2x16 | anonymous public owners | full+2tree | yes | 5639 | 20 | 3 | - | 1543 B | 4719 | 5201 | 987 | 21 | buffered |  |
| 2x16 | anonymous public owners | full+4credential-shared | yes | 5709 | 22 | 3 | - | 1613 B | 4723 | 5201 | 1053 | 23 | buffered |  |
| 2x16 | anonymous public owners | full+4credential-disjoint | yes | 5805 | 25 | 3 | - | 1709 B | 4723 | 5201 | 1149 | 26 | buffered |  |
| 2x16 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 2x16 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 2x16 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 3x8 | confidential signer | min | yes | 2746 | 10 | 1 | - |  | 2295 | 2529 | 518 | 11 | inline |  |
| 3x8 | confidential signer | full | yes | 3336 | 21 | 3 | 3 |  | 2384 | 2574 | 1019 | 22 | inline |  |
| 3x8 | confidential signer | full+spl | yes | 3704 | 28 | 3 | - |  | 2516 | 2578 | 1255 | 29 | inline |  |
| 3x8 | confidential signer | full+data | yes | 4130 | 21 | 3 | - | 34 B | 3178 | 3352 | 1019 | 22 | buffered |  |
| 3x8 | confidential signer | full+reply | yes | 3336 | 21 | 3 | - |  | 2384 | 2574 | 1019 | 22 | inline |  |
| 3x8 | confidential signer | full+2tree | yes | 3342 | 21 | 3 | - |  | 2389 | 2578 | 1020 | 22 | inline |  |
| 3x8 | confidential signer | full+4credential-shared | yes | 3412 | 23 | 3 | - |  | 2393 | 2578 | 1086 | 24 | inline |  |
| 3x8 | confidential signer | full+4credential-disjoint | yes | 3508 | 26 | 3 | - |  | 2393 | 2578 | 1182 | 27 | inline |  |
| 3x8 | confidential in-proof | min | yes | 2841 | 10 | 1 | - |  | 2391 | 2626 | 517 | 11 | inline |  |
| 3x8 | confidential in-proof | full | yes | 3335 | 20 | 2 | 3 |  | 2480 | 2671 | 922 | 21 | inline |  |
| 3x8 | confidential in-proof | full+spl | yes | 3703 | 27 | 2 | - |  | 2612 | 2675 | 1158 | 28 | inline |  |
| 3x8 | confidential in-proof | full+data | yes | 4129 | 20 | 2 | - | 33 B | 3274 | 3449 | 922 | 21 | buffered |  |
| 3x8 | confidential in-proof | full+reply | yes | 3335 | 20 | 2 | - |  | 2480 | 2671 | 922 | 21 | inline |  |
| 3x8 | confidential in-proof | full+2tree | yes | 3341 | 20 | 2 | - |  | 2485 | 2675 | 923 | 21 | inline |  |
| 3x8 | confidential in-proof | full+4credential-shared | yes | 3411 | 22 | 2 | - |  | 2489 | 2675 | 989 | 23 | inline |  |
| 3x8 | confidential in-proof | full+4credential-disjoint | yes | 3507 | 25 | 2 | - |  | 2489 | 2675 | 1085 | 26 | inline |  |
| 3x8 | anonymous hidden | min | yes | 3105 | 10 | 1 | - |  | 2655 | 2920 | 517 | 11 | inline |  |
| 3x8 | anonymous hidden | full | yes | 3575 | 17 | 2 | 3 |  | 2816 | 3047 | 826 | 18 | inline |  |
| 3x8 | anonymous hidden | full+spl | yes | 3943 | 24 | 2 | - |  | 2948 | 3051 | 1062 | 25 | inline |  |
| 3x8 | anonymous hidden | full+data | yes | 4369 | 17 | 2 | - | 273 B | 3610 | 3825 | 826 | 18 | buffered |  |
| 3x8 | anonymous hidden | full+reply | yes | 4256 | 17 | 2 | - | 160 B | 3497 | 3726 | 826 | 18 | buffered |  |
| 3x8 | anonymous hidden | full+2tree | yes | 3581 | 17 | 2 | - |  | 2821 | 3051 | 827 | 18 | inline |  |
| 3x8 | anonymous hidden | full+4credential-shared | yes | 3651 | 19 | 2 | - |  | 2825 | 3051 | 893 | 20 | inline |  |
| 3x8 | anonymous hidden | full+4credential-disjoint | yes | 3747 | 22 | 2 | - |  | 2825 | 3051 | 989 | 23 | inline |  |
| 3x8 | anonymous public owners | min | yes | 3042 | 10 | 1 | - |  | 2591 | 2823 | 518 | 11 | inline |  |
| 3x8 | anonymous public owners | full | yes | 3704 | 21 | 3 | 3 |  | 2752 | 2950 | 1019 | 22 | inline |  |
| 3x8 | anonymous public owners | full+spl | yes | 4072 | 28 | 3 | - |  | 2884 | 2954 | 1255 | 29 | inline |  |
| 3x8 | anonymous public owners | full+data | yes | 4498 | 21 | 3 | - | 402 B | 3546 | 3728 | 1019 | 22 | buffered |  |
| 3x8 | anonymous public owners | full+reply | yes | 4385 | 21 | 3 | - | 289 B | 3433 | 3629 | 1019 | 22 | buffered |  |
| 3x8 | anonymous public owners | full+2tree | yes | 3710 | 21 | 3 | - |  | 2757 | 2954 | 1020 | 22 | inline |  |
| 3x8 | anonymous public owners | full+4credential-shared | yes | 3780 | 23 | 3 | - |  | 2761 | 2954 | 1086 | 24 | inline |  |
| 3x8 | anonymous public owners | full+4credential-disjoint | yes | 3876 | 26 | 3 | - |  | 2761 | 2954 | 1182 | 27 | inline |  |
| 3x8 | confidential entry | min | yes | 3354 | 10 | 1 | - |  | 2903 | 3137 | 518 | 11 | inline |  |
| 3x8 | confidential entry | full | yes | 3944 | 21 | 3 | 2 |  | 2992 | 3182 | 1019 | 22 | inline |  |
| 3x8 | confidential entry | full+spl | yes | 4312 | 28 | 3 | - | 216 B | 3124 | 3186 | 1255 | 29 | buffered |  |
| 3x8 | confidential entry | full+data | yes | 4738 | 21 | 3 | - | 642 B | 3786 | 3960 | 1019 | 22 | buffered |  |
| 3x8 | confidential entry | full+reply | yes | 3944 | 21 | 3 | - |  | 2992 | 3182 | 1019 | 22 | inline |  |
| 3x8 | confidential entry | full+2tree | yes | 3950 | 21 | 3 | - |  | 2997 | 3186 | 1020 | 22 | inline |  |
| 3x8 | confidential entry | full+4credential-shared | yes | 4020 | 23 | 3 | - |  | 3001 | 3186 | 1086 | 24 | inline |  |
| 3x8 | confidential entry | full+4credential-disjoint | yes | 4116 | 26 | 3 | - | 20 B | 3001 | 3186 | 1182 | 27 | buffered |  |
| 3x8 | anonymous entry | min | yes | 3745 | 10 | 1 | - |  | 3295 | 3528 | 517 | 11 | inline |  |
| 3x8 | anonymous entry | full | yes | 4215 | 17 | 2 | none | 119 B | 3456 | 3655 | 826 | 18 | buffered |  |
| 3x8 | anonymous entry | full+spl | yes | 4583 | 24 | 2 | - | 487 B | 3588 | 3659 | 1062 | 25 | buffered |  |
| 3x8 | anonymous entry | full+data | yes | 5009 | 17 | 2 | - | 913 B | 4250 | 4433 | 826 | 18 | buffered |  |
| 3x8 | anonymous entry | full+reply | yes | 4896 | 17 | 2 | - | 800 B | 4137 | 4334 | 826 | 18 | buffered |  |
| 3x8 | anonymous entry | full+2tree | yes | 4221 | 17 | 2 | - | 125 B | 3461 | 3659 | 827 | 18 | buffered |  |
| 3x8 | anonymous entry | full+4credential-shared | yes | 4291 | 19 | 2 | - | 195 B | 3465 | 3659 | 893 | 20 | buffered |  |
| 3x8 | anonymous entry | full+4credential-disjoint | yes | 4387 | 22 | 2 | - | 291 B | 3465 | 3659 | 989 | 23 | buffered |  |
| 3x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 3x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 4x2 | confidential signer | min | yes | 1509 | 11 | 1 | - |  | 1025 | 1044 | 551 | 12 | inline |  |
| 4x2 | confidential signer | full | yes | 2099 | 22 | 3 | 4 |  | 1114 | 1089 | 1052 | 23 | inline |  |
| 4x2 | confidential signer | full+spl | yes | 2467 | 29 | 3 | - |  | 1246 | 1093 | 1288 | 30 | inline |  |
| 4x2 | confidential signer | full+data | yes | 2299 | 22 | 3 | - |  | 1314 | 1285 | 1052 | 23 | inline |  |
| 4x2 | confidential signer | full+reply | yes | 2099 | 22 | 3 | - |  | 1114 | 1089 | 1052 | 23 | inline |  |
| 4x2 | confidential signer | full+2tree | yes | 2105 | 22 | 3 | - |  | 1119 | 1093 | 1053 | 23 | inline |  |
| 4x2 | confidential signer | full+4credential-shared | yes | 2175 | 24 | 3 | - |  | 1123 | 1093 | 1119 | 25 | inline |  |
| 4x2 | confidential signer | full+4credential-disjoint | yes | 2271 | 27 | 3 | - |  | 1123 | 1093 | 1215 | 28 | inline |  |
| 4x2 | confidential in-proof | min | yes | 1604 | 11 | 1 | - |  | 1121 | 1141 | 550 | 12 | inline |  |
| 4x2 | confidential in-proof | full | yes | 2098 | 21 | 2 | 4 |  | 1210 | 1186 | 955 | 22 | inline |  |
| 4x2 | confidential in-proof | full+spl | yes | 2466 | 28 | 2 | - |  | 1342 | 1190 | 1191 | 29 | inline |  |
| 4x2 | confidential in-proof | full+data | yes | 2298 | 21 | 2 | - |  | 1410 | 1382 | 955 | 22 | inline |  |
| 4x2 | confidential in-proof | full+reply | yes | 2098 | 21 | 2 | - |  | 1210 | 1186 | 955 | 22 | inline |  |
| 4x2 | confidential in-proof | full+2tree | yes | 2104 | 21 | 2 | - |  | 1215 | 1190 | 956 | 22 | inline |  |
| 4x2 | confidential in-proof | full+4credential-shared | yes | 2174 | 23 | 2 | - |  | 1219 | 1190 | 1022 | 24 | inline |  |
| 4x2 | confidential in-proof | full+4credential-disjoint | yes | 2270 | 26 | 2 | - |  | 1219 | 1190 | 1118 | 27 | inline |  |
| 4x2 | anonymous hidden | min | yes | 1676 | 11 | 1 | - |  | 1193 | 1243 | 550 | 12 | inline |  |
| 4x2 | anonymous hidden | full | yes | 2146 | 18 | 2 | 4 |  | 1354 | 1370 | 859 | 19 | inline |  |
| 4x2 | anonymous hidden | full+spl | yes | 2514 | 25 | 2 | - |  | 1486 | 1374 | 1095 | 26 | inline |  |
| 4x2 | anonymous hidden | full+data | yes | 2346 | 18 | 2 | - |  | 1554 | 1566 | 859 | 19 | inline |  |
| 4x2 | anonymous hidden | full+reply | yes | 2245 | 18 | 2 | - |  | 1453 | 1467 | 859 | 19 | inline |  |
| 4x2 | anonymous hidden | full+2tree | yes | 2152 | 18 | 2 | - |  | 1359 | 1374 | 860 | 19 | inline |  |
| 4x2 | anonymous hidden | full+4credential-shared | yes | 2222 | 20 | 2 | - |  | 1363 | 1374 | 926 | 21 | inline |  |
| 4x2 | anonymous hidden | full+4credential-disjoint | yes | 2318 | 23 | 2 | - |  | 1363 | 1374 | 1022 | 24 | inline |  |
| 4x2 | anonymous public owners | min | yes | 1613 | 11 | 1 | - |  | 1129 | 1146 | 551 | 12 | inline |  |
| 4x2 | anonymous public owners | full | yes | 2275 | 22 | 3 | 4 |  | 1290 | 1273 | 1052 | 23 | inline |  |
| 4x2 | anonymous public owners | full+spl | yes | 2643 | 29 | 3 | - |  | 1422 | 1277 | 1288 | 30 | inline |  |
| 4x2 | anonymous public owners | full+data | yes | 2475 | 22 | 3 | - |  | 1490 | 1469 | 1052 | 23 | inline |  |
| 4x2 | anonymous public owners | full+reply | yes | 2374 | 22 | 3 | - |  | 1389 | 1370 | 1052 | 23 | inline |  |
| 4x2 | anonymous public owners | full+2tree | yes | 2281 | 22 | 3 | - |  | 1295 | 1277 | 1053 | 23 | inline |  |
| 4x2 | anonymous public owners | full+4credential-shared | yes | 2351 | 24 | 3 | - |  | 1299 | 1277 | 1119 | 25 | inline |  |
| 4x2 | anonymous public owners | full+4credential-disjoint | yes | 2447 | 27 | 3 | - |  | 1299 | 1277 | 1215 | 28 | inline |  |
| 4x2 | confidential entry | min | yes | 2317 | 11 | 1 | - |  | 1833 | 1852 | 551 | 12 | inline |  |
| 4x2 | confidential entry | full | yes | 2907 | 22 | 3 | 4 |  | 1922 | 1897 | 1052 | 23 | inline |  |
| 4x2 | confidential entry | full+spl | yes | 3275 | 29 | 3 | - |  | 2054 | 1901 | 1288 | 30 | inline |  |
| 4x2 | confidential entry | full+data | yes | 3107 | 22 | 3 | - |  | 2122 | 2093 | 1052 | 23 | inline |  |
| 4x2 | confidential entry | full+reply | yes | 2907 | 22 | 3 | - |  | 1922 | 1897 | 1052 | 23 | inline |  |
| 4x2 | confidential entry | full+2tree | yes | 2913 | 22 | 3 | - |  | 1927 | 1901 | 1053 | 23 | inline |  |
| 4x2 | confidential entry | full+4credential-shared | yes | 2983 | 24 | 3 | - |  | 1931 | 1901 | 1119 | 25 | inline |  |
| 4x2 | confidential entry | full+4credential-disjoint | yes | 3079 | 27 | 3 | - |  | 1931 | 1901 | 1215 | 28 | inline |  |
| 4x2 | anonymous entry | min | yes | 2516 | 11 | 1 | - |  | 2033 | 2051 | 550 | 12 | inline |  |
| 4x2 | anonymous entry | full | yes | 2986 | 18 | 2 | 4 |  | 2194 | 2178 | 859 | 19 | inline |  |
| 4x2 | anonymous entry | full+spl | yes | 3354 | 25 | 2 | - |  | 2326 | 2182 | 1095 | 26 | inline |  |
| 4x2 | anonymous entry | full+data | yes | 3186 | 18 | 2 | - |  | 2394 | 2374 | 859 | 19 | inline |  |
| 4x2 | anonymous entry | full+reply | yes | 3085 | 18 | 2 | - |  | 2293 | 2275 | 859 | 19 | inline |  |
| 4x2 | anonymous entry | full+2tree | yes | 2992 | 18 | 2 | - |  | 2199 | 2182 | 860 | 19 | inline |  |
| 4x2 | anonymous entry | full+4credential-shared | yes | 3062 | 20 | 2 | - |  | 2203 | 2182 | 926 | 21 | inline |  |
| 4x2 | anonymous entry | full+4credential-disjoint | yes | 3158 | 23 | 2 | - |  | 2203 | 2182 | 1022 | 24 | inline |  |
| 4x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 4x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 4x4 | confidential signer | min | yes | 1943 | 11 | 1 | - |  | 1459 | 1550 | 551 | 12 | inline |  |
| 4x4 | confidential signer | full | yes | 2533 | 22 | 3 | 4 |  | 1548 | 1595 | 1052 | 23 | inline |  |
| 4x4 | confidential signer | full+spl | yes | 2901 | 29 | 3 | - |  | 1680 | 1599 | 1288 | 30 | inline |  |
| 4x4 | confidential signer | full+data | yes | 2931 | 22 | 3 | - |  | 1946 | 1985 | 1052 | 23 | inline |  |
| 4x4 | confidential signer | full+reply | yes | 2533 | 22 | 3 | - |  | 1548 | 1595 | 1052 | 23 | inline |  |
| 4x4 | confidential signer | full+2tree | yes | 2539 | 22 | 3 | - |  | 1553 | 1599 | 1053 | 23 | inline |  |
| 4x4 | confidential signer | full+4credential-shared | yes | 2609 | 24 | 3 | - |  | 1557 | 1599 | 1119 | 25 | inline |  |
| 4x4 | confidential signer | full+4credential-disjoint | yes | 2705 | 27 | 3 | - |  | 1557 | 1599 | 1215 | 28 | inline |  |
| 4x4 | confidential in-proof | min | yes | 2038 | 11 | 1 | - |  | 1555 | 1647 | 550 | 12 | inline |  |
| 4x4 | confidential in-proof | full | yes | 2532 | 21 | 2 | 4 |  | 1644 | 1692 | 955 | 22 | inline |  |
| 4x4 | confidential in-proof | full+spl | yes | 2900 | 28 | 2 | - |  | 1776 | 1696 | 1191 | 29 | inline |  |
| 4x4 | confidential in-proof | full+data | yes | 2930 | 21 | 2 | - |  | 2042 | 2082 | 955 | 22 | inline |  |
| 4x4 | confidential in-proof | full+reply | yes | 2532 | 21 | 2 | - |  | 1644 | 1692 | 955 | 22 | inline |  |
| 4x4 | confidential in-proof | full+2tree | yes | 2538 | 21 | 2 | - |  | 1649 | 1696 | 956 | 22 | inline |  |
| 4x4 | confidential in-proof | full+4credential-shared | yes | 2608 | 23 | 2 | - |  | 1653 | 1696 | 1022 | 24 | inline |  |
| 4x4 | confidential in-proof | full+4credential-disjoint | yes | 2704 | 26 | 2 | - |  | 1653 | 1696 | 1118 | 27 | inline |  |
| 4x4 | anonymous hidden | min | yes | 2174 | 11 | 1 | - |  | 1691 | 1813 | 550 | 12 | inline |  |
| 4x4 | anonymous hidden | full | yes | 2644 | 18 | 2 | 4 |  | 1852 | 1940 | 859 | 19 | inline |  |
| 4x4 | anonymous hidden | full+spl | yes | 3012 | 25 | 2 | - |  | 1984 | 1944 | 1095 | 26 | inline |  |
| 4x4 | anonymous hidden | full+data | yes | 3042 | 18 | 2 | - |  | 2250 | 2330 | 859 | 19 | inline |  |
| 4x4 | anonymous hidden | full+reply | yes | 2937 | 18 | 2 | - |  | 2145 | 2231 | 859 | 19 | inline |  |
| 4x4 | anonymous hidden | full+2tree | yes | 2650 | 18 | 2 | - |  | 1857 | 1944 | 860 | 19 | inline |  |
| 4x4 | anonymous hidden | full+4credential-shared | yes | 2720 | 20 | 2 | - |  | 1861 | 1944 | 926 | 21 | inline |  |
| 4x4 | anonymous hidden | full+4credential-disjoint | yes | 2816 | 23 | 2 | - |  | 1861 | 1944 | 1022 | 24 | inline |  |
| 4x4 | anonymous public owners | min | yes | 2111 | 11 | 1 | - |  | 1627 | 1716 | 551 | 12 | inline |  |
| 4x4 | anonymous public owners | full | yes | 2773 | 22 | 3 | 4 |  | 1788 | 1843 | 1052 | 23 | inline |  |
| 4x4 | anonymous public owners | full+spl | yes | 3141 | 29 | 3 | - |  | 1920 | 1847 | 1288 | 30 | inline |  |
| 4x4 | anonymous public owners | full+data | yes | 3171 | 22 | 3 | - |  | 2186 | 2233 | 1052 | 23 | inline |  |
| 4x4 | anonymous public owners | full+reply | yes | 3066 | 22 | 3 | - |  | 2081 | 2134 | 1052 | 23 | inline |  |
| 4x4 | anonymous public owners | full+2tree | yes | 2779 | 22 | 3 | - |  | 1793 | 1847 | 1053 | 23 | inline |  |
| 4x4 | anonymous public owners | full+4credential-shared | yes | 2849 | 24 | 3 | - |  | 1797 | 1847 | 1119 | 25 | inline |  |
| 4x4 | anonymous public owners | full+4credential-disjoint | yes | 2945 | 27 | 3 | - |  | 1797 | 1847 | 1215 | 28 | inline |  |
| 4x4 | confidential entry | min | yes | 2751 | 11 | 1 | - |  | 2267 | 2358 | 551 | 12 | inline |  |
| 4x4 | confidential entry | full | yes | 3341 | 22 | 3 | 4 |  | 2356 | 2403 | 1052 | 23 | inline |  |
| 4x4 | confidential entry | full+spl | yes | 3709 | 29 | 3 | - |  | 2488 | 2407 | 1288 | 30 | inline |  |
| 4x4 | confidential entry | full+data | yes | 3739 | 22 | 3 | - |  | 2754 | 2793 | 1052 | 23 | inline |  |
| 4x4 | confidential entry | full+reply | yes | 3341 | 22 | 3 | - |  | 2356 | 2403 | 1052 | 23 | inline |  |
| 4x4 | confidential entry | full+2tree | yes | 3347 | 22 | 3 | - |  | 2361 | 2407 | 1053 | 23 | inline |  |
| 4x4 | confidential entry | full+4credential-shared | yes | 3417 | 24 | 3 | - |  | 2365 | 2407 | 1119 | 25 | inline |  |
| 4x4 | confidential entry | full+4credential-disjoint | yes | 3513 | 27 | 3 | - |  | 2365 | 2407 | 1215 | 28 | inline |  |
| 4x4 | anonymous entry | min | yes | 3014 | 11 | 1 | - |  | 2531 | 2621 | 550 | 12 | inline |  |
| 4x4 | anonymous entry | full | yes | 3484 | 18 | 2 | 4 |  | 2692 | 2748 | 859 | 19 | inline |  |
| 4x4 | anonymous entry | full+spl | yes | 3852 | 25 | 2 | - |  | 2824 | 2752 | 1095 | 26 | inline |  |
| 4x4 | anonymous entry | full+data | yes | 3882 | 18 | 2 | - |  | 3090 | 3138 | 859 | 19 | inline |  |
| 4x4 | anonymous entry | full+reply | yes | 3777 | 18 | 2 | - |  | 2985 | 3039 | 859 | 19 | inline |  |
| 4x4 | anonymous entry | full+2tree | yes | 3490 | 18 | 2 | - |  | 2697 | 2752 | 860 | 19 | inline |  |
| 4x4 | anonymous entry | full+4credential-shared | yes | 3560 | 20 | 2 | - |  | 2701 | 2752 | 926 | 21 | inline |  |
| 4x4 | anonymous entry | full+4credential-disjoint | yes | 3656 | 23 | 2 | - |  | 2701 | 2752 | 1022 | 24 | inline |  |
| 4x4 | delegate | min | yes | 1943 | 11 | 1 | - |  | 1459 | 1550 | 551 | 12 | inline |  |
| 4x4 | delegate | full | yes | 2321 | 18 | 2 | - |  | 1532 | 1595 | 856 | 19 | inline |  |
| 4x4 | delegate | full+spl | yes | 2561 | 25 | 2 | - |  | 1536 | 1599 | 1092 | 26 | inline |  |
| 4x4 | delegate | full+data | yes | 2719 | 18 | 2 | - |  | 1930 | 1985 | 856 | 19 | inline |  |
| 4x4 | delegate | full+reply | yes | 2321 | 18 | 2 | - |  | 1532 | 1595 | 856 | 19 | inline |  |
| 4x4 | delegate | full+2tree | yes | 2327 | 18 | 2 | - |  | 1537 | 1599 | 857 | 19 | inline |  |
| 4x4 | delegate | full+4credential-shared | yes | 2397 | 20 | 2 | - |  | 1541 | 1599 | 923 | 21 | inline |  |
| 4x4 | delegate | full+4credential-disjoint | yes | 2493 | 23 | 2 | - |  | 1541 | 1599 | 1019 | 24 | inline |  |
| 4x4 | anonymous delegate | min | yes | 2111 | 11 | 1 | - |  | 1627 | 1716 | 551 | 12 | inline |  |
| 4x4 | anonymous delegate | full | yes | 2561 | 18 | 2 | - |  | 1772 | 1843 | 856 | 19 | inline |  |
| 4x4 | anonymous delegate | full+spl | yes | 2801 | 25 | 2 | - |  | 1776 | 1847 | 1092 | 26 | inline |  |
| 4x4 | anonymous delegate | full+data | yes | 2959 | 18 | 2 | - |  | 2170 | 2233 | 856 | 19 | inline |  |
| 4x4 | anonymous delegate | full+reply | yes | 2854 | 18 | 2 | - |  | 2065 | 2134 | 856 | 19 | inline |  |
| 4x4 | anonymous delegate | full+2tree | yes | 2567 | 18 | 2 | - |  | 1777 | 1847 | 857 | 19 | inline |  |
| 4x4 | anonymous delegate | full+4credential-shared | yes | 2637 | 20 | 2 | - |  | 1781 | 1847 | 923 | 21 | inline |  |
| 4x4 | anonymous delegate | full+4credential-disjoint | yes | 2733 | 23 | 2 | - |  | 1781 | 1847 | 1019 | 24 | inline |  |
| 4x8 | confidential signer | min | yes | 2811 | 11 | 1 | - |  | 2327 | 2562 | 551 | 12 | inline |  |
| 4x8 | confidential signer | full | yes | 3401 | 22 | 3 | 4 |  | 2416 | 2607 | 1052 | 23 | inline |  |
| 4x8 | confidential signer | full+spl | yes | 3769 | 29 | 3 | - |  | 2548 | 2611 | 1288 | 30 | inline |  |
| 4x8 | confidential signer | full+data | yes | 4195 | 22 | 3 | - | 99 B | 3210 | 3385 | 1052 | 23 | buffered |  |
| 4x8 | confidential signer | full+reply | yes | 3401 | 22 | 3 | - |  | 2416 | 2607 | 1052 | 23 | inline |  |
| 4x8 | confidential signer | full+2tree | yes | 3407 | 22 | 3 | - |  | 2421 | 2611 | 1053 | 23 | inline |  |
| 4x8 | confidential signer | full+4credential-shared | yes | 3477 | 24 | 3 | - |  | 2425 | 2611 | 1119 | 25 | inline |  |
| 4x8 | confidential signer | full+4credential-disjoint | yes | 3573 | 27 | 3 | - |  | 2425 | 2611 | 1215 | 28 | inline |  |
| 4x8 | confidential in-proof | min | yes | 2906 | 11 | 1 | - |  | 2423 | 2659 | 550 | 12 | inline |  |
| 4x8 | confidential in-proof | full | yes | 3400 | 21 | 2 | 4 |  | 2512 | 2704 | 955 | 22 | inline |  |
| 4x8 | confidential in-proof | full+spl | yes | 3768 | 28 | 2 | - |  | 2644 | 2708 | 1191 | 29 | inline |  |
| 4x8 | confidential in-proof | full+data | yes | 4194 | 21 | 2 | - | 98 B | 3306 | 3482 | 955 | 22 | buffered |  |
| 4x8 | confidential in-proof | full+reply | yes | 3400 | 21 | 2 | - |  | 2512 | 2704 | 955 | 22 | inline |  |
| 4x8 | confidential in-proof | full+2tree | yes | 3406 | 21 | 2 | - |  | 2517 | 2708 | 956 | 22 | inline |  |
| 4x8 | confidential in-proof | full+4credential-shared | yes | 3476 | 23 | 2 | - |  | 2521 | 2708 | 1022 | 24 | inline |  |
| 4x8 | confidential in-proof | full+4credential-disjoint | yes | 3572 | 26 | 2 | - |  | 2521 | 2708 | 1118 | 27 | inline |  |
| 4x8 | anonymous hidden | min | yes | 3170 | 11 | 1 | - |  | 2687 | 2953 | 550 | 12 | inline |  |
| 4x8 | anonymous hidden | full | yes | 3640 | 18 | 2 | 4 |  | 2848 | 3080 | 859 | 19 | inline |  |
| 4x8 | anonymous hidden | full+spl | yes | 4008 | 25 | 2 | - |  | 2980 | 3084 | 1095 | 26 | inline |  |
| 4x8 | anonymous hidden | full+data | yes | 4434 | 18 | 2 | - | 338 B | 3642 | 3858 | 859 | 19 | buffered |  |
| 4x8 | anonymous hidden | full+reply | yes | 4321 | 18 | 2 | - | 225 B | 3529 | 3759 | 859 | 19 | buffered |  |
| 4x8 | anonymous hidden | full+2tree | yes | 3646 | 18 | 2 | - |  | 2853 | 3084 | 860 | 19 | inline |  |
| 4x8 | anonymous hidden | full+4credential-shared | yes | 3716 | 20 | 2 | - |  | 2857 | 3084 | 926 | 21 | inline |  |
| 4x8 | anonymous hidden | full+4credential-disjoint | yes | 3812 | 23 | 2 | - |  | 2857 | 3084 | 1022 | 24 | inline |  |
| 4x8 | anonymous public owners | min | yes | 3107 | 11 | 1 | - |  | 2623 | 2856 | 551 | 12 | inline |  |
| 4x8 | anonymous public owners | full | yes | 3769 | 22 | 3 | 4 |  | 2784 | 2983 | 1052 | 23 | inline |  |
| 4x8 | anonymous public owners | full+spl | yes | 4137 | 29 | 3 | - | 41 B | 2916 | 2987 | 1288 | 30 | buffered |  |
| 4x8 | anonymous public owners | full+data | yes | 4563 | 22 | 3 | - | 467 B | 3578 | 3761 | 1052 | 23 | buffered |  |
| 4x8 | anonymous public owners | full+reply | yes | 4450 | 22 | 3 | - | 354 B | 3465 | 3662 | 1052 | 23 | buffered |  |
| 4x8 | anonymous public owners | full+2tree | yes | 3775 | 22 | 3 | - |  | 2789 | 2987 | 1053 | 23 | inline |  |
| 4x8 | anonymous public owners | full+4credential-shared | yes | 3845 | 24 | 3 | - |  | 2793 | 2987 | 1119 | 25 | inline |  |
| 4x8 | anonymous public owners | full+4credential-disjoint | yes | 3941 | 27 | 3 | - |  | 2793 | 2987 | 1215 | 28 | inline |  |
| 4x8 | confidential entry | min | yes | 3619 | 11 | 1 | - |  | 3135 | 3370 | 551 | 12 | inline |  |
| 4x8 | confidential entry | full | yes | 4209 | 22 | 3 | none | 113 B | 3224 | 3415 | 1052 | 23 | buffered |  |
| 4x8 | confidential entry | full+spl | yes | 4577 | 29 | 3 | - | 481 B | 3356 | 3419 | 1288 | 30 | buffered |  |
| 4x8 | confidential entry | full+data | yes | 5003 | 22 | 3 | - | 907 B | 4018 | 4193 | 1052 | 23 | buffered |  |
| 4x8 | confidential entry | full+reply | yes | 4209 | 22 | 3 | - | 113 B | 3224 | 3415 | 1052 | 23 | buffered |  |
| 4x8 | confidential entry | full+2tree | yes | 4215 | 22 | 3 | - | 119 B | 3229 | 3419 | 1053 | 23 | buffered |  |
| 4x8 | confidential entry | full+4credential-shared | yes | 4285 | 24 | 3 | - | 189 B | 3233 | 3419 | 1119 | 25 | buffered |  |
| 4x8 | confidential entry | full+4credential-disjoint | yes | 4381 | 27 | 3 | - | 285 B | 3233 | 3419 | 1215 | 28 | buffered |  |
| 4x8 | anonymous entry | min | yes | 4010 | 11 | 1 | - |  | 3527 | 3761 | 550 | 12 | inline |  |
| 4x8 | anonymous entry | full | yes | 4480 | 18 | 2 | none | 384 B | 3688 | 3888 | 859 | 19 | buffered |  |
| 4x8 | anonymous entry | full+spl | yes | 4848 | 25 | 2 | - | 752 B | 3820 | 3892 | 1095 | 26 | buffered |  |
| 4x8 | anonymous entry | full+data | yes | 5274 | 18 | 2 | - | 1178 B | 4482 | 4666 | 859 | 19 | buffered |  |
| 4x8 | anonymous entry | full+reply | yes | 5161 | 18 | 2 | - | 1065 B | 4369 | 4567 | 859 | 19 | buffered |  |
| 4x8 | anonymous entry | full+2tree | yes | 4486 | 18 | 2 | - | 390 B | 3693 | 3892 | 860 | 19 | buffered |  |
| 4x8 | anonymous entry | full+4credential-shared | yes | 4556 | 20 | 2 | - | 460 B | 3697 | 3892 | 926 | 21 | buffered |  |
| 4x8 | anonymous entry | full+4credential-disjoint | yes | 4652 | 23 | 2 | - | 556 B | 3697 | 3892 | 1022 | 24 | buffered |  |
| 4x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 4x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x2 | confidential signer | min | yes | 1574 | 12 | 1 | - |  | 1057 | 1077 | 584 | 13 | inline |  |
| 5x2 | confidential signer | full | yes | 2164 | 23 | 3 | 5 |  | 1146 | 1122 | 1085 | 24 | inline |  |
| 5x2 | confidential signer | full+spl | yes | 2532 | 30 | 3 | - |  | 1278 | 1126 | 1321 | 31 | inline |  |
| 5x2 | confidential signer | full+data | yes | 2364 | 23 | 3 | - |  | 1346 | 1318 | 1085 | 24 | inline |  |
| 5x2 | confidential signer | full+reply | yes | 2164 | 23 | 3 | - |  | 1146 | 1122 | 1085 | 24 | inline |  |
| 5x2 | confidential signer | full+2tree | yes | 2170 | 23 | 3 | - |  | 1151 | 1126 | 1086 | 24 | inline |  |
| 5x2 | confidential signer | full+4credential-shared | yes | 2240 | 25 | 3 | - |  | 1155 | 1126 | 1152 | 26 | inline |  |
| 5x2 | confidential signer | full+4credential-disjoint | yes | 2336 | 28 | 3 | - |  | 1155 | 1126 | 1248 | 29 | inline |  |
| 5x2 | confidential in-proof | min | yes | 1669 | 12 | 1 | - |  | 1153 | 1174 | 583 | 13 | inline |  |
| 5x2 | confidential in-proof | full | yes | 2163 | 22 | 2 | 5 |  | 1242 | 1219 | 988 | 23 | inline |  |
| 5x2 | confidential in-proof | full+spl | yes | 2531 | 29 | 2 | - |  | 1374 | 1223 | 1224 | 30 | inline |  |
| 5x2 | confidential in-proof | full+data | yes | 2363 | 22 | 2 | - |  | 1442 | 1415 | 988 | 23 | inline |  |
| 5x2 | confidential in-proof | full+reply | yes | 2163 | 22 | 2 | - |  | 1242 | 1219 | 988 | 23 | inline |  |
| 5x2 | confidential in-proof | full+2tree | yes | 2169 | 22 | 2 | - |  | 1247 | 1223 | 989 | 23 | inline |  |
| 5x2 | confidential in-proof | full+4credential-shared | yes | 2239 | 24 | 2 | - |  | 1251 | 1223 | 1055 | 25 | inline |  |
| 5x2 | confidential in-proof | full+4credential-disjoint | yes | 2335 | 27 | 2 | - |  | 1251 | 1223 | 1151 | 28 | inline |  |
| 5x2 | anonymous hidden | min | yes | 1741 | 12 | 1 | - |  | 1225 | 1276 | 583 | 13 | inline |  |
| 5x2 | anonymous hidden | full | yes | 2211 | 19 | 2 | 5 |  | 1386 | 1403 | 892 | 20 | inline |  |
| 5x2 | anonymous hidden | full+spl | yes | 2579 | 26 | 2 | - |  | 1518 | 1407 | 1128 | 27 | inline |  |
| 5x2 | anonymous hidden | full+data | yes | 2411 | 19 | 2 | - |  | 1586 | 1599 | 892 | 20 | inline |  |
| 5x2 | anonymous hidden | full+reply | yes | 2310 | 19 | 2 | - |  | 1485 | 1500 | 892 | 20 | inline |  |
| 5x2 | anonymous hidden | full+2tree | yes | 2217 | 19 | 2 | - |  | 1391 | 1407 | 893 | 20 | inline |  |
| 5x2 | anonymous hidden | full+4credential-shared | yes | 2287 | 21 | 2 | - |  | 1395 | 1407 | 959 | 22 | inline |  |
| 5x2 | anonymous hidden | full+4credential-disjoint | yes | 2383 | 24 | 2 | - |  | 1395 | 1407 | 1055 | 25 | inline |  |
| 5x2 | anonymous public owners | min | yes | 1678 | 12 | 1 | - |  | 1161 | 1179 | 584 | 13 | inline |  |
| 5x2 | anonymous public owners | full | yes | 2340 | 23 | 3 | 5 |  | 1322 | 1306 | 1085 | 24 | inline |  |
| 5x2 | anonymous public owners | full+spl | yes | 2708 | 30 | 3 | - |  | 1454 | 1310 | 1321 | 31 | inline |  |
| 5x2 | anonymous public owners | full+data | yes | 2540 | 23 | 3 | - |  | 1522 | 1502 | 1085 | 24 | inline |  |
| 5x2 | anonymous public owners | full+reply | yes | 2439 | 23 | 3 | - |  | 1421 | 1403 | 1085 | 24 | inline |  |
| 5x2 | anonymous public owners | full+2tree | yes | 2346 | 23 | 3 | - |  | 1327 | 1310 | 1086 | 24 | inline |  |
| 5x2 | anonymous public owners | full+4credential-shared | yes | 2416 | 25 | 3 | - |  | 1331 | 1310 | 1152 | 26 | inline |  |
| 5x2 | anonymous public owners | full+4credential-disjoint | yes | 2512 | 28 | 3 | - |  | 1331 | 1310 | 1248 | 29 | inline |  |
| 5x2 | confidential entry | min | yes | 2582 | 12 | 1 | - |  | 2065 | 2085 | 584 | 13 | inline |  |
| 5x2 | confidential entry | full | yes | 3172 | 23 | 3 | 5 |  | 2154 | 2130 | 1085 | 24 | inline |  |
| 5x2 | confidential entry | full+spl | yes | 3540 | 30 | 3 | - |  | 2286 | 2134 | 1321 | 31 | inline |  |
| 5x2 | confidential entry | full+data | yes | 3372 | 23 | 3 | - |  | 2354 | 2326 | 1085 | 24 | inline |  |
| 5x2 | confidential entry | full+reply | yes | 3172 | 23 | 3 | - |  | 2154 | 2130 | 1085 | 24 | inline |  |
| 5x2 | confidential entry | full+2tree | yes | 3178 | 23 | 3 | - |  | 2159 | 2134 | 1086 | 24 | inline |  |
| 5x2 | confidential entry | full+4credential-shared | yes | 3248 | 25 | 3 | - |  | 2163 | 2134 | 1152 | 26 | inline |  |
| 5x2 | confidential entry | full+4credential-disjoint | yes | 3344 | 28 | 3 | - |  | 2163 | 2134 | 1248 | 29 | inline |  |
| 5x2 | anonymous entry | min | yes | 2781 | 12 | 1 | - |  | 2265 | 2284 | 583 | 13 | inline |  |
| 5x2 | anonymous entry | full | yes | 3251 | 19 | 2 | 5 |  | 2426 | 2411 | 892 | 20 | inline |  |
| 5x2 | anonymous entry | full+spl | yes | 3619 | 26 | 2 | - |  | 2558 | 2415 | 1128 | 27 | inline |  |
| 5x2 | anonymous entry | full+data | yes | 3451 | 19 | 2 | - |  | 2626 | 2607 | 892 | 20 | inline |  |
| 5x2 | anonymous entry | full+reply | yes | 3350 | 19 | 2 | - |  | 2525 | 2508 | 892 | 20 | inline |  |
| 5x2 | anonymous entry | full+2tree | yes | 3257 | 19 | 2 | - |  | 2431 | 2415 | 893 | 20 | inline |  |
| 5x2 | anonymous entry | full+4credential-shared | yes | 3327 | 21 | 2 | - |  | 2435 | 2415 | 959 | 22 | inline |  |
| 5x2 | anonymous entry | full+4credential-disjoint | yes | 3423 | 24 | 2 | - |  | 2435 | 2415 | 1055 | 25 | inline |  |
| 5x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x4 | confidential signer | min | yes | 2008 | 12 | 1 | - |  | 1491 | 1583 | 584 | 13 | inline |  |
| 5x4 | confidential signer | full | yes | 2598 | 23 | 3 | 5 |  | 1580 | 1628 | 1085 | 24 | inline |  |
| 5x4 | confidential signer | full+spl | yes | 2966 | 30 | 3 | - |  | 1712 | 1632 | 1321 | 31 | inline |  |
| 5x4 | confidential signer | full+data | yes | 2996 | 23 | 3 | - |  | 1978 | 2018 | 1085 | 24 | inline |  |
| 5x4 | confidential signer | full+reply | yes | 2598 | 23 | 3 | - |  | 1580 | 1628 | 1085 | 24 | inline |  |
| 5x4 | confidential signer | full+2tree | yes | 2604 | 23 | 3 | - |  | 1585 | 1632 | 1086 | 24 | inline |  |
| 5x4 | confidential signer | full+4credential-shared | yes | 2674 | 25 | 3 | - |  | 1589 | 1632 | 1152 | 26 | inline |  |
| 5x4 | confidential signer | full+4credential-disjoint | yes | 2770 | 28 | 3 | - |  | 1589 | 1632 | 1248 | 29 | inline |  |
| 5x4 | confidential in-proof | min | yes | 2103 | 12 | 1 | - |  | 1587 | 1680 | 583 | 13 | inline |  |
| 5x4 | confidential in-proof | full | yes | 2597 | 22 | 2 | 5 |  | 1676 | 1725 | 988 | 23 | inline |  |
| 5x4 | confidential in-proof | full+spl | yes | 2965 | 29 | 2 | - |  | 1808 | 1729 | 1224 | 30 | inline |  |
| 5x4 | confidential in-proof | full+data | yes | 2995 | 22 | 2 | - |  | 2074 | 2115 | 988 | 23 | inline |  |
| 5x4 | confidential in-proof | full+reply | yes | 2597 | 22 | 2 | - |  | 1676 | 1725 | 988 | 23 | inline |  |
| 5x4 | confidential in-proof | full+2tree | yes | 2603 | 22 | 2 | - |  | 1681 | 1729 | 989 | 23 | inline |  |
| 5x4 | confidential in-proof | full+4credential-shared | yes | 2673 | 24 | 2 | - |  | 1685 | 1729 | 1055 | 25 | inline |  |
| 5x4 | confidential in-proof | full+4credential-disjoint | yes | 2769 | 27 | 2 | - |  | 1685 | 1729 | 1151 | 28 | inline |  |
| 5x4 | anonymous hidden | min | yes | 2239 | 12 | 1 | - |  | 1723 | 1846 | 583 | 13 | inline |  |
| 5x4 | anonymous hidden | full | yes | 2709 | 19 | 2 | 5 |  | 1884 | 1973 | 892 | 20 | inline |  |
| 5x4 | anonymous hidden | full+spl | yes | 3077 | 26 | 2 | - |  | 2016 | 1977 | 1128 | 27 | inline |  |
| 5x4 | anonymous hidden | full+data | yes | 3107 | 19 | 2 | - |  | 2282 | 2363 | 892 | 20 | inline |  |
| 5x4 | anonymous hidden | full+reply | yes | 3002 | 19 | 2 | - |  | 2177 | 2264 | 892 | 20 | inline |  |
| 5x4 | anonymous hidden | full+2tree | yes | 2715 | 19 | 2 | - |  | 1889 | 1977 | 893 | 20 | inline |  |
| 5x4 | anonymous hidden | full+4credential-shared | yes | 2785 | 21 | 2 | - |  | 1893 | 1977 | 959 | 22 | inline |  |
| 5x4 | anonymous hidden | full+4credential-disjoint | yes | 2881 | 24 | 2 | - |  | 1893 | 1977 | 1055 | 25 | inline |  |
| 5x4 | anonymous public owners | min | yes | 2176 | 12 | 1 | - |  | 1659 | 1749 | 584 | 13 | inline |  |
| 5x4 | anonymous public owners | full | yes | 2838 | 23 | 3 | 5 |  | 1820 | 1876 | 1085 | 24 | inline |  |
| 5x4 | anonymous public owners | full+spl | yes | 3206 | 30 | 3 | - |  | 1952 | 1880 | 1321 | 31 | inline |  |
| 5x4 | anonymous public owners | full+data | yes | 3236 | 23 | 3 | - |  | 2218 | 2266 | 1085 | 24 | inline |  |
| 5x4 | anonymous public owners | full+reply | yes | 3131 | 23 | 3 | - |  | 2113 | 2167 | 1085 | 24 | inline |  |
| 5x4 | anonymous public owners | full+2tree | yes | 2844 | 23 | 3 | - |  | 1825 | 1880 | 1086 | 24 | inline |  |
| 5x4 | anonymous public owners | full+4credential-shared | yes | 2914 | 25 | 3 | - |  | 1829 | 1880 | 1152 | 26 | inline |  |
| 5x4 | anonymous public owners | full+4credential-disjoint | yes | 3010 | 28 | 3 | - |  | 1829 | 1880 | 1248 | 29 | inline |  |
| 5x4 | confidential entry | min | yes | 3016 | 12 | 1 | - |  | 2499 | 2591 | 584 | 13 | inline |  |
| 5x4 | confidential entry | full | yes | 3606 | 23 | 3 | 5 |  | 2588 | 2636 | 1085 | 24 | inline |  |
| 5x4 | confidential entry | full+spl | yes | 3974 | 30 | 3 | - |  | 2720 | 2640 | 1321 | 31 | inline |  |
| 5x4 | confidential entry | full+data | yes | 4004 | 23 | 3 | - |  | 2986 | 3026 | 1085 | 24 | inline |  |
| 5x4 | confidential entry | full+reply | yes | 3606 | 23 | 3 | - |  | 2588 | 2636 | 1085 | 24 | inline |  |
| 5x4 | confidential entry | full+2tree | yes | 3612 | 23 | 3 | - |  | 2593 | 2640 | 1086 | 24 | inline |  |
| 5x4 | confidential entry | full+4credential-shared | yes | 3682 | 25 | 3 | - |  | 2597 | 2640 | 1152 | 26 | inline |  |
| 5x4 | confidential entry | full+4credential-disjoint | yes | 3778 | 28 | 3 | - |  | 2597 | 2640 | 1248 | 29 | inline |  |
| 5x4 | anonymous entry | min | yes | 3279 | 12 | 1 | - |  | 2763 | 2854 | 583 | 13 | inline |  |
| 5x4 | anonymous entry | full | yes | 3749 | 19 | 2 | 3 |  | 2924 | 2981 | 892 | 20 | inline |  |
| 5x4 | anonymous entry | full+spl | yes | 4117 | 26 | 2 | - | 21 B | 3056 | 2985 | 1128 | 27 | buffered |  |
| 5x4 | anonymous entry | full+data | yes | 4147 | 19 | 2 | - | 51 B | 3322 | 3371 | 892 | 20 | buffered |  |
| 5x4 | anonymous entry | full+reply | yes | 4042 | 19 | 2 | - |  | 3217 | 3272 | 892 | 20 | inline |  |
| 5x4 | anonymous entry | full+2tree | yes | 3755 | 19 | 2 | - |  | 2929 | 2985 | 893 | 20 | inline |  |
| 5x4 | anonymous entry | full+4credential-shared | yes | 3825 | 21 | 2 | - |  | 2933 | 2985 | 959 | 22 | inline |  |
| 5x4 | anonymous entry | full+4credential-disjoint | yes | 3921 | 24 | 2 | - |  | 2933 | 2985 | 1055 | 25 | inline |  |
| 5x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 4x16 | confidential signer | min | yes | 4549 | 11 | 1 | - | 453 B | 4065 | 4586 | 551 | 12 | buffered |  |
| 4x16 | confidential signer | full | yes | 5139 | 22 | 3 | none | 1043 B | 4154 | 4631 | 1052 | 23 | buffered |  |
| 4x16 | confidential signer | full+spl | yes | 5507 | 29 | 3 | - | 1411 B | 4286 | 4635 | 1288 | 30 | buffered |  |
| 4x16 | confidential signer | full+data | yes | 6725 | 22 | 3 | - | 2629 B | 5740 | 6185 | 1052 | 23 | buffered |  |
| 4x16 | confidential signer | full+reply | yes | 5139 | 22 | 3 | - | 1043 B | 4154 | 4631 | 1052 | 23 | buffered |  |
| 4x16 | confidential signer | full+2tree | yes | 5145 | 22 | 3 | - | 1049 B | 4159 | 4635 | 1053 | 23 | buffered |  |
| 4x16 | confidential signer | full+4credential-shared | yes | 5215 | 24 | 3 | - | 1119 B | 4163 | 4635 | 1119 | 25 | buffered |  |
| 4x16 | confidential signer | full+4credential-disjoint | yes | 5311 | 27 | 3 | - | 1215 B | 4163 | 4635 | 1215 | 28 | buffered |  |
| 4x16 | confidential in-proof | min | yes | 4644 | 11 | 1 | - | 548 B | 4161 | 4683 | 550 | 12 | buffered |  |
| 4x16 | confidential in-proof | full | yes | 5138 | 21 | 2 | none | 1042 B | 4250 | 4728 | 955 | 22 | buffered |  |
| 4x16 | confidential in-proof | full+spl | yes | 5506 | 28 | 2 | - | 1410 B | 4382 | 4732 | 1191 | 29 | buffered |  |
| 4x16 | confidential in-proof | full+data | yes | 6724 | 21 | 2 | - | 2628 B | 5836 | 6282 | 955 | 22 | buffered |  |
| 4x16 | confidential in-proof | full+reply | yes | 5138 | 21 | 2 | - | 1042 B | 4250 | 4728 | 955 | 22 | buffered |  |
| 4x16 | confidential in-proof | full+2tree | yes | 5144 | 21 | 2 | - | 1048 B | 4255 | 4732 | 956 | 22 | buffered |  |
| 4x16 | confidential in-proof | full+4credential-shared | yes | 5214 | 23 | 2 | - | 1118 B | 4259 | 4732 | 1022 | 24 | buffered |  |
| 4x16 | confidential in-proof | full+4credential-disjoint | yes | 5310 | 26 | 2 | - | 1214 B | 4259 | 4732 | 1118 | 27 | buffered |  |
| 4x16 | anonymous hidden | min | yes | 5164 | 11 | 1 | - | 1068 B | 4681 | 5233 | 550 | 12 | buffered |  |
| 4x16 | anonymous hidden | full | yes | 5634 | 18 | 2 | none | 1538 B | 4842 | 5360 | 859 | 19 | buffered |  |
| 4x16 | anonymous hidden | full+spl | yes | 6002 | 25 | 2 | - | 1906 B | 4974 | 5364 | 1095 | 26 | buffered |  |
| 4x16 | anonymous hidden | full+data | yes | 7220 | 18 | 2 | - | 3124 B | 6428 | 6914 | 859 | 19 | buffered |  |
| 4x16 | anonymous hidden | full+reply | yes | 7091 | 18 | 2 | - | 2995 B | 6299 | 6815 | 859 | 19 | buffered |  |
| 4x16 | anonymous hidden | full+2tree | yes | 5640 | 18 | 2 | - | 1544 B | 4847 | 5364 | 860 | 19 | buffered |  |
| 4x16 | anonymous hidden | full+4credential-shared | yes | 5710 | 20 | 2 | - | 1614 B | 4851 | 5364 | 926 | 21 | buffered |  |
| 4x16 | anonymous hidden | full+4credential-disjoint | yes | 5806 | 23 | 2 | - | 1710 B | 4851 | 5364 | 1022 | 24 | buffered |  |
| 4x16 | anonymous public owners | min | yes | 5101 | 11 | 1 | - | 1005 B | 4617 | 5136 | 551 | 12 | buffered |  |
| 4x16 | anonymous public owners | full | yes | 5763 | 22 | 3 | none | 1667 B | 4778 | 5263 | 1052 | 23 | buffered |  |
| 4x16 | anonymous public owners | full+spl | yes | 6131 | 29 | 3 | - | 2035 B | 4910 | 5267 | 1288 | 30 | buffered |  |
| 4x16 | anonymous public owners | full+data | yes | 7349 | 22 | 3 | - | 3253 B | 6364 | 6817 | 1052 | 23 | buffered |  |
| 4x16 | anonymous public owners | full+reply | yes | 7220 | 22 | 3 | - | 3124 B | 6235 | 6718 | 1052 | 23 | buffered |  |
| 4x16 | anonymous public owners | full+2tree | yes | 5769 | 22 | 3 | - | 1673 B | 4783 | 5267 | 1053 | 23 | buffered |  |
| 4x16 | anonymous public owners | full+4credential-shared | yes | 5839 | 24 | 3 | - | 1743 B | 4787 | 5267 | 1119 | 25 | buffered |  |
| 4x16 | anonymous public owners | full+4credential-disjoint | yes | 5935 | 27 | 3 | - | 1839 B | 4787 | 5267 | 1215 | 28 | buffered |  |
| 4x16 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 4x16 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 4x16 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x8 | confidential signer | min | yes | 2876 | 12 | 1 | - |  | 2359 | 2595 | 584 | 13 | inline |  |
| 5x8 | confidential signer | full | yes | 3466 | 23 | 3 | 5 |  | 2448 | 2640 | 1085 | 24 | inline |  |
| 5x8 | confidential signer | full+spl | yes | 3834 | 30 | 3 | - |  | 2580 | 2644 | 1321 | 31 | inline |  |
| 5x8 | confidential signer | full+data | yes | 4260 | 23 | 3 | - | 164 B | 3242 | 3418 | 1085 | 24 | buffered |  |
| 5x8 | confidential signer | full+reply | yes | 3466 | 23 | 3 | - |  | 2448 | 2640 | 1085 | 24 | inline |  |
| 5x8 | confidential signer | full+2tree | yes | 3472 | 23 | 3 | - |  | 2453 | 2644 | 1086 | 24 | inline |  |
| 5x8 | confidential signer | full+4credential-shared | yes | 3542 | 25 | 3 | - |  | 2457 | 2644 | 1152 | 26 | inline |  |
| 5x8 | confidential signer | full+4credential-disjoint | yes | 3638 | 28 | 3 | - |  | 2457 | 2644 | 1248 | 29 | inline |  |
| 5x8 | confidential in-proof | min | yes | 2971 | 12 | 1 | - |  | 2455 | 2692 | 583 | 13 | inline |  |
| 5x8 | confidential in-proof | full | yes | 3465 | 22 | 2 | 5 |  | 2544 | 2737 | 988 | 23 | inline |  |
| 5x8 | confidential in-proof | full+spl | yes | 3833 | 29 | 2 | - |  | 2676 | 2741 | 1224 | 30 | inline |  |
| 5x8 | confidential in-proof | full+data | yes | 4259 | 22 | 2 | - | 163 B | 3338 | 3515 | 988 | 23 | buffered |  |
| 5x8 | confidential in-proof | full+reply | yes | 3465 | 22 | 2 | - |  | 2544 | 2737 | 988 | 23 | inline |  |
| 5x8 | confidential in-proof | full+2tree | yes | 3471 | 22 | 2 | - |  | 2549 | 2741 | 989 | 23 | inline |  |
| 5x8 | confidential in-proof | full+4credential-shared | yes | 3541 | 24 | 2 | - |  | 2553 | 2741 | 1055 | 25 | inline |  |
| 5x8 | confidential in-proof | full+4credential-disjoint | yes | 3637 | 27 | 2 | - |  | 2553 | 2741 | 1151 | 28 | inline |  |
| 5x8 | anonymous hidden | min | yes | 3235 | 12 | 1 | - |  | 2719 | 2986 | 583 | 13 | inline |  |
| 5x8 | anonymous hidden | full | yes | 3705 | 19 | 2 | 4 |  | 2880 | 3113 | 892 | 20 | inline |  |
| 5x8 | anonymous hidden | full+spl | yes | 4073 | 26 | 2 | - |  | 3012 | 3117 | 1128 | 27 | inline |  |
| 5x8 | anonymous hidden | full+data | yes | 4499 | 19 | 2 | - | 403 B | 3674 | 3891 | 892 | 20 | buffered |  |
| 5x8 | anonymous hidden | full+reply | yes | 4386 | 19 | 2 | - | 290 B | 3561 | 3792 | 892 | 20 | buffered |  |
| 5x8 | anonymous hidden | full+2tree | yes | 3711 | 19 | 2 | - |  | 2885 | 3117 | 893 | 20 | inline |  |
| 5x8 | anonymous hidden | full+4credential-shared | yes | 3781 | 21 | 2 | - |  | 2889 | 3117 | 959 | 22 | inline |  |
| 5x8 | anonymous hidden | full+4credential-disjoint | yes | 3877 | 24 | 2 | - |  | 2889 | 3117 | 1055 | 25 | inline |  |
| 5x8 | anonymous public owners | min | yes | 3172 | 12 | 1 | - |  | 2655 | 2889 | 584 | 13 | inline |  |
| 5x8 | anonymous public owners | full | yes | 3834 | 23 | 3 | 3 |  | 2816 | 3016 | 1085 | 24 | inline |  |
| 5x8 | anonymous public owners | full+spl | yes | 4202 | 30 | 3 | - | 106 B | 2948 | 3020 | 1321 | 31 | buffered |  |
| 5x8 | anonymous public owners | full+data | yes | 4628 | 23 | 3 | - | 532 B | 3610 | 3794 | 1085 | 24 | buffered |  |
| 5x8 | anonymous public owners | full+reply | yes | 4515 | 23 | 3 | - | 419 B | 3497 | 3695 | 1085 | 24 | buffered |  |
| 5x8 | anonymous public owners | full+2tree | yes | 3840 | 23 | 3 | - |  | 2821 | 3020 | 1086 | 24 | inline |  |
| 5x8 | anonymous public owners | full+4credential-shared | yes | 3910 | 25 | 3 | - |  | 2825 | 3020 | 1152 | 26 | inline |  |
| 5x8 | anonymous public owners | full+4credential-disjoint | yes | 4006 | 28 | 3 | - |  | 2825 | 3020 | 1248 | 29 | inline |  |
| 5x8 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 6x2 | confidential signer | min | yes | 1639 | 13 | 1 | - |  | 1089 | 1110 | 617 | 14 | inline |  |
| 6x2 | confidential signer | full | yes | 2229 | 24 | 3 | 6 |  | 1178 | 1155 | 1118 | 25 | inline |  |
| 6x2 | confidential signer | full+spl | yes | 2597 | 31 | 3 | - |  | 1310 | 1159 | 1354 | 32 | inline |  |
| 6x2 | confidential signer | full+data | yes | 2429 | 24 | 3 | - |  | 1378 | 1351 | 1118 | 25 | inline |  |
| 6x2 | confidential signer | full+reply | yes | 2229 | 24 | 3 | - |  | 1178 | 1155 | 1118 | 25 | inline |  |
| 6x2 | confidential signer | full+2tree | yes | 2235 | 24 | 3 | - |  | 1183 | 1159 | 1119 | 25 | inline |  |
| 6x2 | confidential signer | full+4credential-shared | yes | 2305 | 26 | 3 | - |  | 1187 | 1159 | 1185 | 27 | inline |  |
| 6x2 | confidential signer | full+4credential-disjoint | yes | 2401 | 29 | 3 | - |  | 1187 | 1159 | 1281 | 30 | inline |  |
| 6x2 | confidential in-proof | min | yes | 1734 | 13 | 1 | - |  | 1185 | 1207 | 616 | 14 | inline |  |
| 6x2 | confidential in-proof | full | yes | 2228 | 23 | 2 | 6 |  | 1274 | 1252 | 1021 | 24 | inline |  |
| 6x2 | confidential in-proof | full+spl | yes | 2596 | 30 | 2 | - |  | 1406 | 1256 | 1257 | 31 | inline |  |
| 6x2 | confidential in-proof | full+data | yes | 2428 | 23 | 2 | - |  | 1474 | 1448 | 1021 | 24 | inline |  |
| 6x2 | confidential in-proof | full+reply | yes | 2228 | 23 | 2 | - |  | 1274 | 1252 | 1021 | 24 | inline |  |
| 6x2 | confidential in-proof | full+2tree | yes | 2234 | 23 | 2 | - |  | 1279 | 1256 | 1022 | 24 | inline |  |
| 6x2 | confidential in-proof | full+4credential-shared | yes | 2304 | 25 | 2 | - |  | 1283 | 1256 | 1088 | 26 | inline |  |
| 6x2 | confidential in-proof | full+4credential-disjoint | yes | 2400 | 28 | 2 | - |  | 1283 | 1256 | 1184 | 29 | inline |  |
| 6x2 | anonymous hidden | min | yes | 1806 | 13 | 1 | - |  | 1257 | 1309 | 616 | 14 | inline |  |
| 6x2 | anonymous hidden | full | yes | 2276 | 20 | 2 | 6 |  | 1418 | 1436 | 925 | 21 | inline |  |
| 6x2 | anonymous hidden | full+spl | yes | 2644 | 27 | 2 | - |  | 1550 | 1440 | 1161 | 28 | inline |  |
| 6x2 | anonymous hidden | full+data | yes | 2476 | 20 | 2 | - |  | 1618 | 1632 | 925 | 21 | inline |  |
| 6x2 | anonymous hidden | full+reply | yes | 2375 | 20 | 2 | - |  | 1517 | 1533 | 925 | 21 | inline |  |
| 6x2 | anonymous hidden | full+2tree | yes | 2282 | 20 | 2 | - |  | 1423 | 1440 | 926 | 21 | inline |  |
| 6x2 | anonymous hidden | full+4credential-shared | yes | 2352 | 22 | 2 | - |  | 1427 | 1440 | 992 | 23 | inline |  |
| 6x2 | anonymous hidden | full+4credential-disjoint | yes | 2448 | 25 | 2 | - |  | 1427 | 1440 | 1088 | 26 | inline |  |
| 6x2 | anonymous public owners | min | yes | 1743 | 13 | 1 | - |  | 1193 | 1212 | 617 | 14 | inline |  |
| 6x2 | anonymous public owners | full | yes | 2405 | 24 | 3 | 6 |  | 1354 | 1339 | 1118 | 25 | inline |  |
| 6x2 | anonymous public owners | full+spl | yes | 2773 | 31 | 3 | - |  | 1486 | 1343 | 1354 | 32 | inline |  |
| 6x2 | anonymous public owners | full+data | yes | 2605 | 24 | 3 | - |  | 1554 | 1535 | 1118 | 25 | inline |  |
| 6x2 | anonymous public owners | full+reply | yes | 2504 | 24 | 3 | - |  | 1453 | 1436 | 1118 | 25 | inline |  |
| 6x2 | anonymous public owners | full+2tree | yes | 2411 | 24 | 3 | - |  | 1359 | 1343 | 1119 | 25 | inline |  |
| 6x2 | anonymous public owners | full+4credential-shared | yes | 2481 | 26 | 3 | - |  | 1363 | 1343 | 1185 | 27 | inline |  |
| 6x2 | anonymous public owners | full+4credential-disjoint | yes | 2577 | 29 | 3 | - |  | 1363 | 1343 | 1281 | 30 | inline |  |
| 6x2 | confidential entry | min | yes | 2847 | 13 | 1 | - |  | 2297 | 2318 | 617 | 14 | inline |  |
| 6x2 | confidential entry | full | yes | 3437 | 24 | 3 | 6 |  | 2386 | 2363 | 1118 | 25 | inline |  |
| 6x2 | confidential entry | full+spl | yes | 3805 | 31 | 3 | - |  | 2518 | 2367 | 1354 | 32 | inline |  |
| 6x2 | confidential entry | full+data | yes | 3637 | 24 | 3 | - |  | 2586 | 2559 | 1118 | 25 | inline |  |
| 6x2 | confidential entry | full+reply | yes | 3437 | 24 | 3 | - |  | 2386 | 2363 | 1118 | 25 | inline |  |
| 6x2 | confidential entry | full+2tree | yes | 3443 | 24 | 3 | - |  | 2391 | 2367 | 1119 | 25 | inline |  |
| 6x2 | confidential entry | full+4credential-shared | yes | 3513 | 26 | 3 | - |  | 2395 | 2367 | 1185 | 27 | inline |  |
| 6x2 | confidential entry | full+4credential-disjoint | yes | 3609 | 29 | 3 | - |  | 2395 | 2367 | 1281 | 30 | inline |  |
| 6x2 | anonymous entry | min | yes | 3046 | 13 | 1 | - |  | 2497 | 2517 | 616 | 14 | inline |  |
| 6x2 | anonymous entry | full | yes | 3516 | 20 | 2 | 5 |  | 2658 | 2644 | 925 | 21 | inline |  |
| 6x2 | anonymous entry | full+spl | yes | 3884 | 27 | 2 | - |  | 2790 | 2648 | 1161 | 28 | inline |  |
| 6x2 | anonymous entry | full+data | yes | 3716 | 20 | 2 | - |  | 2858 | 2840 | 925 | 21 | inline |  |
| 6x2 | anonymous entry | full+reply | yes | 3615 | 20 | 2 | - |  | 2757 | 2741 | 925 | 21 | inline |  |
| 6x2 | anonymous entry | full+2tree | yes | 3522 | 20 | 2 | - |  | 2663 | 2648 | 926 | 21 | inline |  |
| 6x2 | anonymous entry | full+4credential-shared | yes | 3592 | 22 | 2 | - |  | 2667 | 2648 | 992 | 23 | inline |  |
| 6x2 | anonymous entry | full+4credential-disjoint | yes | 3688 | 25 | 2 | - |  | 2667 | 2648 | 1088 | 26 | inline |  |
| 6x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 6x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 6x4 | confidential signer | min | yes | 2073 | 13 | 1 | - |  | 1523 | 1616 | 617 | 14 | inline |  |
| 6x4 | confidential signer | full | yes | 2663 | 24 | 3 | 6 |  | 1612 | 1661 | 1118 | 25 | inline |  |
| 6x4 | confidential signer | full+spl | yes | 3031 | 31 | 3 | - |  | 1744 | 1665 | 1354 | 32 | inline |  |
| 6x4 | confidential signer | full+data | yes | 3061 | 24 | 3 | - |  | 2010 | 2051 | 1118 | 25 | inline |  |
| 6x4 | confidential signer | full+reply | yes | 2663 | 24 | 3 | - |  | 1612 | 1661 | 1118 | 25 | inline |  |
| 6x4 | confidential signer | full+2tree | yes | 2669 | 24 | 3 | - |  | 1617 | 1665 | 1119 | 25 | inline |  |
| 6x4 | confidential signer | full+4credential-shared | yes | 2739 | 26 | 3 | - |  | 1621 | 1665 | 1185 | 27 | inline |  |
| 6x4 | confidential signer | full+4credential-disjoint | yes | 2835 | 29 | 3 | - |  | 1621 | 1665 | 1281 | 30 | inline |  |
| 6x4 | confidential in-proof | min | yes | 2168 | 13 | 1 | - |  | 1619 | 1713 | 616 | 14 | inline |  |
| 6x4 | confidential in-proof | full | yes | 2662 | 23 | 2 | 6 |  | 1708 | 1758 | 1021 | 24 | inline |  |
| 6x4 | confidential in-proof | full+spl | yes | 3030 | 30 | 2 | - |  | 1840 | 1762 | 1257 | 31 | inline |  |
| 6x4 | confidential in-proof | full+data | yes | 3060 | 23 | 2 | - |  | 2106 | 2148 | 1021 | 24 | inline |  |
| 6x4 | confidential in-proof | full+reply | yes | 2662 | 23 | 2 | - |  | 1708 | 1758 | 1021 | 24 | inline |  |
| 6x4 | confidential in-proof | full+2tree | yes | 2668 | 23 | 2 | - |  | 1713 | 1762 | 1022 | 24 | inline |  |
| 6x4 | confidential in-proof | full+4credential-shared | yes | 2738 | 25 | 2 | - |  | 1717 | 1762 | 1088 | 26 | inline |  |
| 6x4 | confidential in-proof | full+4credential-disjoint | yes | 2834 | 28 | 2 | - |  | 1717 | 1762 | 1184 | 29 | inline |  |
| 6x4 | anonymous hidden | min | yes | 2304 | 13 | 1 | - |  | 1755 | 1879 | 616 | 14 | inline |  |
| 6x4 | anonymous hidden | full | yes | 2774 | 20 | 2 | 6 |  | 1916 | 2006 | 925 | 21 | inline |  |
| 6x4 | anonymous hidden | full+spl | yes | 3142 | 27 | 2 | - |  | 2048 | 2010 | 1161 | 28 | inline |  |
| 6x4 | anonymous hidden | full+data | yes | 3172 | 20 | 2 | - |  | 2314 | 2396 | 925 | 21 | inline |  |
| 6x4 | anonymous hidden | full+reply | yes | 3067 | 20 | 2 | - |  | 2209 | 2297 | 925 | 21 | inline |  |
| 6x4 | anonymous hidden | full+2tree | yes | 2780 | 20 | 2 | - |  | 1921 | 2010 | 926 | 21 | inline |  |
| 6x4 | anonymous hidden | full+4credential-shared | yes | 2850 | 22 | 2 | - |  | 1925 | 2010 | 992 | 23 | inline |  |
| 6x4 | anonymous hidden | full+4credential-disjoint | yes | 2946 | 25 | 2 | - |  | 1925 | 2010 | 1088 | 26 | inline |  |
| 6x4 | anonymous public owners | min | yes | 2241 | 13 | 1 | - |  | 1691 | 1782 | 617 | 14 | inline |  |
| 6x4 | anonymous public owners | full | yes | 2903 | 24 | 3 | 6 |  | 1852 | 1909 | 1118 | 25 | inline |  |
| 6x4 | anonymous public owners | full+spl | yes | 3271 | 31 | 3 | - |  | 1984 | 1913 | 1354 | 32 | inline |  |
| 6x4 | anonymous public owners | full+data | yes | 3301 | 24 | 3 | - |  | 2250 | 2299 | 1118 | 25 | inline |  |
| 6x4 | anonymous public owners | full+reply | yes | 3196 | 24 | 3 | - |  | 2145 | 2200 | 1118 | 25 | inline |  |
| 6x4 | anonymous public owners | full+2tree | yes | 2909 | 24 | 3 | - |  | 1857 | 1913 | 1119 | 25 | inline |  |
| 6x4 | anonymous public owners | full+4credential-shared | yes | 2979 | 26 | 3 | - |  | 1861 | 1913 | 1185 | 27 | inline |  |
| 6x4 | anonymous public owners | full+4credential-disjoint | yes | 3075 | 29 | 3 | - |  | 1861 | 1913 | 1281 | 30 | inline |  |
| 6x4 | confidential entry | min | yes | 3281 | 13 | 1 | - |  | 2731 | 2824 | 617 | 14 | inline |  |
| 6x4 | confidential entry | full | yes | 3871 | 24 | 3 | 3 |  | 2820 | 2869 | 1118 | 25 | inline |  |
| 6x4 | confidential entry | full+spl | yes | 4239 | 31 | 3 | - | 143 B | 2952 | 2873 | 1354 | 32 | buffered |  |
| 6x4 | confidential entry | full+data | yes | 4269 | 24 | 3 | - | 173 B | 3218 | 3259 | 1118 | 25 | buffered |  |
| 6x4 | confidential entry | full+reply | yes | 3871 | 24 | 3 | - |  | 2820 | 2869 | 1118 | 25 | inline |  |
| 6x4 | confidential entry | full+2tree | yes | 3877 | 24 | 3 | - |  | 2825 | 2873 | 1119 | 25 | inline |  |
| 6x4 | confidential entry | full+4credential-shared | yes | 3947 | 26 | 3 | - |  | 2829 | 2873 | 1185 | 27 | inline |  |
| 6x4 | confidential entry | full+4credential-disjoint | yes | 4043 | 29 | 3 | - |  | 2829 | 2873 | 1281 | 30 | inline |  |
| 6x4 | anonymous entry | min | yes | 3544 | 13 | 1 | - |  | 2995 | 3087 | 616 | 14 | inline |  |
| 6x4 | anonymous entry | full | yes | 4014 | 20 | 2 | 0 |  | 3156 | 3214 | 925 | 21 | inline |  |
| 6x4 | anonymous entry | full+spl | yes | 4382 | 27 | 2 | - | 286 B | 3288 | 3218 | 1161 | 28 | buffered |  |
| 6x4 | anonymous entry | full+data | yes | 4412 | 20 | 2 | - | 316 B | 3554 | 3604 | 925 | 21 | buffered |  |
| 6x4 | anonymous entry | full+reply | yes | 4307 | 20 | 2 | - | 211 B | 3449 | 3505 | 925 | 21 | buffered |  |
| 6x4 | anonymous entry | full+2tree | yes | 4020 | 20 | 2 | - |  | 3161 | 3218 | 926 | 21 | inline |  |
| 6x4 | anonymous entry | full+4credential-shared | yes | 4090 | 22 | 2 | - |  | 3165 | 3218 | 992 | 23 | inline |  |
| 6x4 | anonymous entry | full+4credential-disjoint | yes | 4186 | 25 | 2 | - | 90 B | 3165 | 3218 | 1088 | 26 | buffered |  |
| 6x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 6x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x16 | confidential signer | min | yes | 4614 | 12 | 1 | - | 518 B | 4097 | 4619 | 584 | 13 | buffered |  |
| 5x16 | confidential signer | full | yes | 5204 | 23 | 3 | none | 1108 B | 4186 | 4664 | 1085 | 24 | buffered |  |
| 5x16 | confidential signer | full+spl | yes | 5572 | 30 | 3 | - | 1476 B | 4318 | 4668 | 1321 | 31 | buffered |  |
| 5x16 | confidential signer | full+data | yes | 6790 | 23 | 3 | - | 2694 B | 5772 | 6218 | 1085 | 24 | buffered |  |
| 5x16 | confidential signer | full+reply | yes | 5204 | 23 | 3 | - | 1108 B | 4186 | 4664 | 1085 | 24 | buffered |  |
| 5x16 | confidential signer | full+2tree | yes | 5210 | 23 | 3 | - | 1114 B | 4191 | 4668 | 1086 | 24 | buffered |  |
| 5x16 | confidential signer | full+4credential-shared | yes | 5280 | 25 | 3 | - | 1184 B | 4195 | 4668 | 1152 | 26 | buffered |  |
| 5x16 | confidential signer | full+4credential-disjoint | yes | 5376 | 28 | 3 | - | 1280 B | 4195 | 4668 | 1248 | 29 | buffered |  |
| 5x16 | confidential in-proof | min | yes | 4709 | 12 | 1 | - | 613 B | 4193 | 4716 | 583 | 13 | buffered |  |
| 5x16 | confidential in-proof | full | yes | 5203 | 22 | 2 | none | 1107 B | 4282 | 4761 | 988 | 23 | buffered |  |
| 5x16 | confidential in-proof | full+spl | yes | 5571 | 29 | 2 | - | 1475 B | 4414 | 4765 | 1224 | 30 | buffered |  |
| 5x16 | confidential in-proof | full+data | yes | 6789 | 22 | 2 | - | 2693 B | 5868 | 6315 | 988 | 23 | buffered |  |
| 5x16 | confidential in-proof | full+reply | yes | 5203 | 22 | 2 | - | 1107 B | 4282 | 4761 | 988 | 23 | buffered |  |
| 5x16 | confidential in-proof | full+2tree | yes | 5209 | 22 | 2 | - | 1113 B | 4287 | 4765 | 989 | 23 | buffered |  |
| 5x16 | confidential in-proof | full+4credential-shared | yes | 5279 | 24 | 2 | - | 1183 B | 4291 | 4765 | 1055 | 25 | buffered |  |
| 5x16 | confidential in-proof | full+4credential-disjoint | yes | 5375 | 27 | 2 | - | 1279 B | 4291 | 4765 | 1151 | 28 | buffered |  |
| 5x16 | anonymous hidden | min | yes | 5229 | 12 | 1 | - | 1133 B | 4713 | 5266 | 583 | 13 | buffered |  |
| 5x16 | anonymous hidden | full | yes | 5699 | 19 | 2 | none | 1603 B | 4874 | 5393 | 892 | 20 | buffered |  |
| 5x16 | anonymous hidden | full+spl | yes | 6067 | 26 | 2 | - | 1971 B | 5006 | 5397 | 1128 | 27 | buffered |  |
| 5x16 | anonymous hidden | full+data | yes | 7285 | 19 | 2 | - | 3189 B | 6460 | 6947 | 892 | 20 | buffered |  |
| 5x16 | anonymous hidden | full+reply | yes | 7156 | 19 | 2 | - | 3060 B | 6331 | 6848 | 892 | 20 | buffered |  |
| 5x16 | anonymous hidden | full+2tree | yes | 5705 | 19 | 2 | - | 1609 B | 4879 | 5397 | 893 | 20 | buffered |  |
| 5x16 | anonymous hidden | full+4credential-shared | yes | 5775 | 21 | 2 | - | 1679 B | 4883 | 5397 | 959 | 22 | buffered |  |
| 5x16 | anonymous hidden | full+4credential-disjoint | yes | 5871 | 24 | 2 | - | 1775 B | 4883 | 5397 | 1055 | 25 | buffered |  |
| 5x16 | anonymous public owners | min | yes | 5166 | 12 | 1 | - | 1070 B | 4649 | 5169 | 584 | 13 | buffered |  |
| 5x16 | anonymous public owners | full | yes | 5828 | 23 | 3 | none | 1732 B | 4810 | 5296 | 1085 | 24 | buffered |  |
| 5x16 | anonymous public owners | full+spl | yes | 6196 | 30 | 3 | - | 2100 B | 4942 | 5300 | 1321 | 31 | buffered |  |
| 5x16 | anonymous public owners | full+data | yes | 7414 | 23 | 3 | - | 3318 B | 6396 | 6850 | 1085 | 24 | buffered |  |
| 5x16 | anonymous public owners | full+reply | yes | 7285 | 23 | 3 | - | 3189 B | 6267 | 6751 | 1085 | 24 | buffered |  |
| 5x16 | anonymous public owners | full+2tree | yes | 5834 | 23 | 3 | - | 1738 B | 4815 | 5300 | 1086 | 24 | buffered |  |
| 5x16 | anonymous public owners | full+4credential-shared | yes | 5904 | 25 | 3 | - | 1808 B | 4819 | 5300 | 1152 | 26 | buffered |  |
| 5x16 | anonymous public owners | full+4credential-disjoint | yes | 6000 | 28 | 3 | - | 1904 B | 4819 | 5300 | 1248 | 29 | buffered |  |
| 5x16 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 5x16 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x16 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 6x8 | confidential signer | min | yes | 2941 | 13 | 1 | - |  | 2391 | 2628 | 617 | 14 | inline |  |
| 6x8 | confidential signer | full | yes | 3531 | 24 | 3 | 6 |  | 2480 | 2673 | 1118 | 25 | inline |  |
| 6x8 | confidential signer | full+spl | yes | 3899 | 31 | 3 | - |  | 2612 | 2677 | 1354 | 32 | inline |  |
| 6x8 | confidential signer | full+data | yes | 4325 | 24 | 3 | - | 229 B | 3274 | 3451 | 1118 | 25 | buffered |  |
| 6x8 | confidential signer | full+reply | yes | 3531 | 24 | 3 | - |  | 2480 | 2673 | 1118 | 25 | inline |  |
| 6x8 | confidential signer | full+2tree | yes | 3537 | 24 | 3 | - |  | 2485 | 2677 | 1119 | 25 | inline |  |
| 6x8 | confidential signer | full+4credential-shared | yes | 3607 | 26 | 3 | - |  | 2489 | 2677 | 1185 | 27 | inline |  |
| 6x8 | confidential signer | full+4credential-disjoint | yes | 3703 | 29 | 3 | - |  | 2489 | 2677 | 1281 | 30 | inline |  |
| 6x8 | confidential in-proof | min | yes | 3036 | 13 | 1 | - |  | 2487 | 2725 | 616 | 14 | inline |  |
| 6x8 | confidential in-proof | full | yes | 3530 | 23 | 2 | 5 |  | 2576 | 2770 | 1021 | 24 | inline |  |
| 6x8 | confidential in-proof | full+spl | yes | 3898 | 30 | 2 | - |  | 2708 | 2774 | 1257 | 31 | inline |  |
| 6x8 | confidential in-proof | full+data | yes | 4324 | 23 | 2 | - | 228 B | 3370 | 3548 | 1021 | 24 | buffered |  |
| 6x8 | confidential in-proof | full+reply | yes | 3530 | 23 | 2 | - |  | 2576 | 2770 | 1021 | 24 | inline |  |
| 6x8 | confidential in-proof | full+2tree | yes | 3536 | 23 | 2 | - |  | 2581 | 2774 | 1022 | 24 | inline |  |
| 6x8 | confidential in-proof | full+4credential-shared | yes | 3606 | 25 | 2 | - |  | 2585 | 2774 | 1088 | 26 | inline |  |
| 6x8 | confidential in-proof | full+4credential-disjoint | yes | 3702 | 28 | 2 | - |  | 2585 | 2774 | 1184 | 29 | inline |  |
| 6x8 | anonymous hidden | min | yes | 3300 | 13 | 1 | - |  | 2751 | 3019 | 616 | 14 | inline |  |
| 6x8 | anonymous hidden | full | yes | 3770 | 20 | 2 | 3 |  | 2912 | 3146 | 925 | 21 | inline |  |
| 6x8 | anonymous hidden | full+spl | yes | 4138 | 27 | 2 | - | 42 B | 3044 | 3150 | 1161 | 28 | buffered |  |
| 6x8 | anonymous hidden | full+data | yes | 4564 | 20 | 2 | - | 468 B | 3706 | 3924 | 925 | 21 | buffered |  |
| 6x8 | anonymous hidden | full+reply | yes | 4451 | 20 | 2 | - | 355 B | 3593 | 3825 | 925 | 21 | buffered |  |
| 6x8 | anonymous hidden | full+2tree | yes | 3776 | 20 | 2 | - |  | 2917 | 3150 | 926 | 21 | inline |  |
| 6x8 | anonymous hidden | full+4credential-shared | yes | 3846 | 22 | 2 | - |  | 2921 | 3150 | 992 | 23 | inline |  |
| 6x8 | anonymous hidden | full+4credential-disjoint | yes | 3942 | 25 | 2 | - |  | 2921 | 3150 | 1088 | 26 | inline |  |
| 6x8 | anonymous public owners | min | yes | 3237 | 13 | 1 | - |  | 2687 | 2922 | 617 | 14 | inline |  |
| 6x8 | anonymous public owners | full | yes | 3899 | 24 | 3 | 3 |  | 2848 | 3049 | 1118 | 25 | inline |  |
| 6x8 | anonymous public owners | full+spl | yes | 4267 | 31 | 3 | - | 171 B | 2980 | 3053 | 1354 | 32 | buffered |  |
| 6x8 | anonymous public owners | full+data | yes | 4693 | 24 | 3 | - | 597 B | 3642 | 3827 | 1118 | 25 | buffered |  |
| 6x8 | anonymous public owners | full+reply | yes | 4580 | 24 | 3 | - | 484 B | 3529 | 3728 | 1118 | 25 | buffered |  |
| 6x8 | anonymous public owners | full+2tree | yes | 3905 | 24 | 3 | - |  | 2853 | 3053 | 1119 | 25 | inline |  |
| 6x8 | anonymous public owners | full+4credential-shared | yes | 3975 | 26 | 3 | - |  | 2857 | 3053 | 1185 | 27 | inline |  |
| 6x8 | anonymous public owners | full+4credential-disjoint | yes | 4071 | 29 | 3 | - |  | 2857 | 3053 | 1281 | 30 | inline |  |
| 6x8 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 6x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 6x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x2 | confidential signer | min | yes | 1769 | 15 | 1 | - |  | 1153 | 1176 | 683 | 16 | inline |  |
| 8x2 | confidential signer | full | yes | 2359 | 26 | 3 | 8 |  | 1242 | 1221 | 1184 | 27 | inline |  |
| 8x2 | confidential signer | full+spl | yes | 2727 | 33 | 3 | - |  | 1374 | 1225 | 1420 | 34 | inline |  |
| 8x2 | confidential signer | full+data | yes | 2559 | 26 | 3 | - |  | 1442 | 1417 | 1184 | 27 | inline |  |
| 8x2 | confidential signer | full+reply | yes | 2359 | 26 | 3 | - |  | 1242 | 1221 | 1184 | 27 | inline |  |
| 8x2 | confidential signer | full+2tree | yes | 2365 | 26 | 3 | - |  | 1247 | 1225 | 1185 | 27 | inline |  |
| 8x2 | confidential signer | full+4credential-shared | yes | 2435 | 28 | 3 | - |  | 1251 | 1225 | 1251 | 29 | inline |  |
| 8x2 | confidential signer | full+4credential-disjoint | yes | 2531 | 31 | 3 | - |  | 1251 | 1225 | 1347 | 32 | inline |  |
| 8x2 | confidential in-proof | min | yes | 1864 | 15 | 1 | - |  | 1249 | 1273 | 682 | 16 | inline |  |
| 8x2 | confidential in-proof | full | yes | 2358 | 25 | 2 | 8 |  | 1338 | 1318 | 1087 | 26 | inline |  |
| 8x2 | confidential in-proof | full+spl | yes | 2726 | 32 | 2 | - |  | 1470 | 1322 | 1323 | 33 | inline |  |
| 8x2 | confidential in-proof | full+data | yes | 2558 | 25 | 2 | - |  | 1538 | 1514 | 1087 | 26 | inline |  |
| 8x2 | confidential in-proof | full+reply | yes | 2358 | 25 | 2 | - |  | 1338 | 1318 | 1087 | 26 | inline |  |
| 8x2 | confidential in-proof | full+2tree | yes | 2364 | 25 | 2 | - |  | 1343 | 1322 | 1088 | 26 | inline |  |
| 8x2 | confidential in-proof | full+4credential-shared | yes | 2434 | 27 | 2 | - |  | 1347 | 1322 | 1154 | 28 | inline |  |
| 8x2 | confidential in-proof | full+4credential-disjoint | yes | 2530 | 30 | 2 | - |  | 1347 | 1322 | 1250 | 31 | inline |  |
| 8x2 | anonymous hidden | min | yes | 1936 | 15 | 1 | - |  | 1321 | 1375 | 682 | 16 | inline |  |
| 8x2 | anonymous hidden | full | yes | 2406 | 22 | 2 | 8 |  | 1482 | 1502 | 991 | 23 | inline |  |
| 8x2 | anonymous hidden | full+spl | yes | 2774 | 29 | 2 | - |  | 1614 | 1506 | 1227 | 30 | inline |  |
| 8x2 | anonymous hidden | full+data | yes | 2606 | 22 | 2 | - |  | 1682 | 1698 | 991 | 23 | inline |  |
| 8x2 | anonymous hidden | full+reply | yes | 2505 | 22 | 2 | - |  | 1581 | 1599 | 991 | 23 | inline |  |
| 8x2 | anonymous hidden | full+2tree | yes | 2412 | 22 | 2 | - |  | 1487 | 1506 | 992 | 23 | inline |  |
| 8x2 | anonymous hidden | full+4credential-shared | yes | 2482 | 24 | 2 | - |  | 1491 | 1506 | 1058 | 25 | inline |  |
| 8x2 | anonymous hidden | full+4credential-disjoint | yes | 2578 | 27 | 2 | - |  | 1491 | 1506 | 1154 | 28 | inline |  |
| 8x2 | anonymous public owners | min | yes | 1873 | 15 | 1 | - |  | 1257 | 1278 | 683 | 16 | inline |  |
| 8x2 | anonymous public owners | full | yes | 2535 | 26 | 3 | 8 |  | 1418 | 1405 | 1184 | 27 | inline |  |
| 8x2 | anonymous public owners | full+spl | yes | 2903 | 33 | 3 | - |  | 1550 | 1409 | 1420 | 34 | inline |  |
| 8x2 | anonymous public owners | full+data | yes | 2735 | 26 | 3 | - |  | 1618 | 1601 | 1184 | 27 | inline |  |
| 8x2 | anonymous public owners | full+reply | yes | 2634 | 26 | 3 | - |  | 1517 | 1502 | 1184 | 27 | inline |  |
| 8x2 | anonymous public owners | full+2tree | yes | 2541 | 26 | 3 | - |  | 1423 | 1409 | 1185 | 27 | inline |  |
| 8x2 | anonymous public owners | full+4credential-shared | yes | 2611 | 28 | 3 | - |  | 1427 | 1409 | 1251 | 29 | inline |  |
| 8x2 | anonymous public owners | full+4credential-disjoint | yes | 2707 | 31 | 3 | - |  | 1427 | 1409 | 1347 | 32 | inline |  |
| 8x2 | confidential entry | min | yes | 3377 | 15 | 1 | - |  | 2761 | 2784 | 683 | 16 | inline |  |
| 8x2 | confidential entry | full | yes | 3967 | 26 | 3 | 2 |  | 2850 | 2829 | 1184 | 27 | inline |  |
| 8x2 | confidential entry | full+spl | yes | 4335 | 33 | 3 | - | 239 B | 2982 | 2833 | 1420 | 34 | buffered |  |
| 8x2 | confidential entry | full+data | yes | 4167 | 26 | 3 | - | 71 B | 3050 | 3025 | 1184 | 27 | buffered |  |
| 8x2 | confidential entry | full+reply | yes | 3967 | 26 | 3 | - |  | 2850 | 2829 | 1184 | 27 | inline |  |
| 8x2 | confidential entry | full+2tree | yes | 3973 | 26 | 3 | - |  | 2855 | 2833 | 1185 | 27 | inline |  |
| 8x2 | confidential entry | full+4credential-shared | yes | 4043 | 28 | 3 | - |  | 2859 | 2833 | 1251 | 29 | inline |  |
| 8x2 | confidential entry | full+4credential-disjoint | yes | 4139 | 31 | 3 | - | 43 B | 2859 | 2833 | 1347 | 32 | buffered |  |
| 8x2 | anonymous entry | min | yes | 3576 | 15 | 1 | - |  | 2961 | 2983 | 682 | 16 | inline |  |
| 8x2 | anonymous entry | full | yes | 4046 | 22 | 2 | 0 |  | 3122 | 3110 | 991 | 23 | inline |  |
| 8x2 | anonymous entry | full+spl | yes | 4414 | 29 | 2 | - | 318 B | 3254 | 3114 | 1227 | 30 | buffered |  |
| 8x2 | anonymous entry | full+data | yes | 4246 | 22 | 2 | - | 150 B | 3322 | 3306 | 991 | 23 | buffered |  |
| 8x2 | anonymous entry | full+reply | yes | 4145 | 22 | 2 | - | 49 B | 3221 | 3207 | 991 | 23 | buffered |  |
| 8x2 | anonymous entry | full+2tree | yes | 4052 | 22 | 2 | - |  | 3127 | 3114 | 992 | 23 | inline |  |
| 8x2 | anonymous entry | full+4credential-shared | yes | 4122 | 24 | 2 | - | 26 B | 3131 | 3114 | 1058 | 25 | buffered |  |
| 8x2 | anonymous entry | full+4credential-disjoint | yes | 4218 | 27 | 2 | - | 122 B | 3131 | 3114 | 1154 | 28 | buffered |  |
| 8x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x4 | confidential signer | min | yes | 2203 | 15 | 1 | - |  | 1587 | 1682 | 683 | 16 | inline |  |
| 8x4 | confidential signer | full | yes | 2793 | 26 | 3 | 8 |  | 1676 | 1727 | 1184 | 27 | inline |  |
| 8x4 | confidential signer | full+spl | yes | 3161 | 33 | 3 | - |  | 1808 | 1731 | 1420 | 34 | inline |  |
| 8x4 | confidential signer | full+data | yes | 3191 | 26 | 3 | - |  | 2074 | 2117 | 1184 | 27 | inline |  |
| 8x4 | confidential signer | full+reply | yes | 2793 | 26 | 3 | - |  | 1676 | 1727 | 1184 | 27 | inline |  |
| 8x4 | confidential signer | full+2tree | yes | 2799 | 26 | 3 | - |  | 1681 | 1731 | 1185 | 27 | inline |  |
| 8x4 | confidential signer | full+4credential-shared | yes | 2869 | 28 | 3 | - |  | 1685 | 1731 | 1251 | 29 | inline |  |
| 8x4 | confidential signer | full+4credential-disjoint | yes | 2965 | 31 | 3 | - |  | 1685 | 1731 | 1347 | 32 | inline |  |
| 8x4 | confidential in-proof | min | yes | 2298 | 15 | 1 | - |  | 1683 | 1779 | 682 | 16 | inline |  |
| 8x4 | confidential in-proof | full | yes | 2792 | 25 | 2 | 8 |  | 1772 | 1824 | 1087 | 26 | inline |  |
| 8x4 | confidential in-proof | full+spl | yes | 3160 | 32 | 2 | - |  | 1904 | 1828 | 1323 | 33 | inline |  |
| 8x4 | confidential in-proof | full+data | yes | 3190 | 25 | 2 | - |  | 2170 | 2214 | 1087 | 26 | inline |  |
| 8x4 | confidential in-proof | full+reply | yes | 2792 | 25 | 2 | - |  | 1772 | 1824 | 1087 | 26 | inline |  |
| 8x4 | confidential in-proof | full+2tree | yes | 2798 | 25 | 2 | - |  | 1777 | 1828 | 1088 | 26 | inline |  |
| 8x4 | confidential in-proof | full+4credential-shared | yes | 2868 | 27 | 2 | - |  | 1781 | 1828 | 1154 | 28 | inline |  |
| 8x4 | confidential in-proof | full+4credential-disjoint | yes | 2964 | 30 | 2 | - |  | 1781 | 1828 | 1250 | 31 | inline |  |
| 8x4 | anonymous hidden | min | yes | 2434 | 15 | 1 | - |  | 1819 | 1945 | 682 | 16 | inline |  |
| 8x4 | anonymous hidden | full | yes | 2904 | 22 | 2 | 8 |  | 1980 | 2072 | 991 | 23 | inline |  |
| 8x4 | anonymous hidden | full+spl | yes | 3272 | 29 | 2 | - |  | 2112 | 2076 | 1227 | 30 | inline |  |
| 8x4 | anonymous hidden | full+data | yes | 3302 | 22 | 2 | - |  | 2378 | 2462 | 991 | 23 | inline |  |
| 8x4 | anonymous hidden | full+reply | yes | 3197 | 22 | 2 | - |  | 2273 | 2363 | 991 | 23 | inline |  |
| 8x4 | anonymous hidden | full+2tree | yes | 2910 | 22 | 2 | - |  | 1985 | 2076 | 992 | 23 | inline |  |
| 8x4 | anonymous hidden | full+4credential-shared | yes | 2980 | 24 | 2 | - |  | 1989 | 2076 | 1058 | 25 | inline |  |
| 8x4 | anonymous hidden | full+4credential-disjoint | yes | 3076 | 27 | 2 | - |  | 1989 | 2076 | 1154 | 28 | inline |  |
| 8x4 | anonymous public owners | min | yes | 2371 | 15 | 1 | - |  | 1755 | 1848 | 683 | 16 | inline |  |
| 8x4 | anonymous public owners | full | yes | 3033 | 26 | 3 | 8 |  | 1916 | 1975 | 1184 | 27 | inline |  |
| 8x4 | anonymous public owners | full+spl | yes | 3401 | 33 | 3 | - |  | 2048 | 1979 | 1420 | 34 | inline |  |
| 8x4 | anonymous public owners | full+data | yes | 3431 | 26 | 3 | - |  | 2314 | 2365 | 1184 | 27 | inline |  |
| 8x4 | anonymous public owners | full+reply | yes | 3326 | 26 | 3 | - |  | 2209 | 2266 | 1184 | 27 | inline |  |
| 8x4 | anonymous public owners | full+2tree | yes | 3039 | 26 | 3 | - |  | 1921 | 1979 | 1185 | 27 | inline |  |
| 8x4 | anonymous public owners | full+4credential-shared | yes | 3109 | 28 | 3 | - |  | 1925 | 1979 | 1251 | 29 | inline |  |
| 8x4 | anonymous public owners | full+4credential-disjoint | yes | 3205 | 31 | 3 | - |  | 1925 | 1979 | 1347 | 32 | inline |  |
| 8x4 | confidential entry | min | yes | 3811 | 15 | 1 | - |  | 3195 | 3290 | 683 | 16 | inline |  |
| 8x4 | confidential entry | full | yes | 4401 | 26 | 3 | none | 305 B | 3284 | 3335 | 1184 | 27 | buffered |  |
| 8x4 | confidential entry | full+spl | yes | 4769 | 33 | 3 | - | 673 B | 3416 | 3339 | 1420 | 34 | buffered |  |
| 8x4 | confidential entry | full+data | yes | 4799 | 26 | 3 | - | 703 B | 3682 | 3725 | 1184 | 27 | buffered |  |
| 8x4 | confidential entry | full+reply | yes | 4401 | 26 | 3 | - | 305 B | 3284 | 3335 | 1184 | 27 | buffered |  |
| 8x4 | confidential entry | full+2tree | yes | 4407 | 26 | 3 | - | 311 B | 3289 | 3339 | 1185 | 27 | buffered |  |
| 8x4 | confidential entry | full+4credential-shared | yes | 4477 | 28 | 3 | - | 381 B | 3293 | 3339 | 1251 | 29 | buffered |  |
| 8x4 | confidential entry | full+4credential-disjoint | yes | 4573 | 31 | 3 | - | 477 B | 3293 | 3339 | 1347 | 32 | buffered |  |
| 8x4 | anonymous entry | min | yes | 4074 | 15 | 1 | - |  | 3459 | 3553 | 682 | 16 | inline |  |
| 8x4 | anonymous entry | full | yes | 4544 | 22 | 2 | none | 448 B | 3620 | 3680 | 991 | 23 | buffered |  |
| 8x4 | anonymous entry | full+spl | yes | 4912 | 29 | 2 | - | 816 B | 3752 | 3684 | 1227 | 30 | buffered |  |
| 8x4 | anonymous entry | full+data | yes | 4942 | 22 | 2 | - | 846 B | 4018 | 4070 | 991 | 23 | buffered |  |
| 8x4 | anonymous entry | full+reply | yes | 4837 | 22 | 2 | - | 741 B | 3913 | 3971 | 991 | 23 | buffered |  |
| 8x4 | anonymous entry | full+2tree | yes | 4550 | 22 | 2 | - | 454 B | 3625 | 3684 | 992 | 23 | buffered |  |
| 8x4 | anonymous entry | full+4credential-shared | yes | 4620 | 24 | 2 | - | 524 B | 3629 | 3684 | 1058 | 25 | buffered |  |
| 8x4 | anonymous entry | full+4credential-disjoint | yes | 4716 | 27 | 2 | - | 620 B | 3629 | 3684 | 1154 | 28 | buffered |  |
| 8x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x8 | confidential signer | min | yes | 3071 | 15 | 1 | - |  | 2455 | 2694 | 683 | 16 | inline |  |
| 8x8 | confidential signer | full | yes | 3661 | 26 | 3 | 5 |  | 2544 | 2739 | 1184 | 27 | inline |  |
| 8x8 | confidential signer | full+spl | yes | 4029 | 33 | 3 | - |  | 2676 | 2743 | 1420 | 34 | inline |  |
| 8x8 | confidential signer | full+data | yes | 4455 | 26 | 3 | - | 359 B | 3338 | 3517 | 1184 | 27 | buffered |  |
| 8x8 | confidential signer | full+reply | yes | 3661 | 26 | 3 | - |  | 2544 | 2739 | 1184 | 27 | inline |  |
| 8x8 | confidential signer | full+2tree | yes | 3667 | 26 | 3 | - |  | 2549 | 2743 | 1185 | 27 | inline |  |
| 8x8 | confidential signer | full+4credential-shared | yes | 3737 | 28 | 3 | - |  | 2553 | 2743 | 1251 | 29 | inline |  |
| 8x8 | confidential signer | full+4credential-disjoint | yes | 3833 | 31 | 3 | - |  | 2553 | 2743 | 1347 | 32 | inline |  |
| 8x8 | confidential in-proof | min | yes | 3166 | 15 | 1 | - |  | 2551 | 2791 | 682 | 16 | inline |  |
| 8x8 | confidential in-proof | full | yes | 3660 | 25 | 2 | 4 |  | 2640 | 2836 | 1087 | 26 | inline |  |
| 8x8 | confidential in-proof | full+spl | yes | 4028 | 32 | 2 | - |  | 2772 | 2840 | 1323 | 33 | inline |  |
| 8x8 | confidential in-proof | full+data | yes | 4454 | 25 | 2 | - | 358 B | 3434 | 3614 | 1087 | 26 | buffered |  |
| 8x8 | confidential in-proof | full+reply | yes | 3660 | 25 | 2 | - |  | 2640 | 2836 | 1087 | 26 | inline |  |
| 8x8 | confidential in-proof | full+2tree | yes | 3666 | 25 | 2 | - |  | 2645 | 2840 | 1088 | 26 | inline |  |
| 8x8 | confidential in-proof | full+4credential-shared | yes | 3736 | 27 | 2 | - |  | 2649 | 2840 | 1154 | 28 | inline |  |
| 8x8 | confidential in-proof | full+4credential-disjoint | yes | 3832 | 30 | 2 | - |  | 2649 | 2840 | 1250 | 31 | inline |  |
| 8x8 | anonymous hidden | min | yes | 3430 | 15 | 1 | - |  | 2815 | 3085 | 682 | 16 | inline |  |
| 8x8 | anonymous hidden | full | yes | 3900 | 22 | 2 | 2 |  | 2976 | 3212 | 991 | 23 | inline |  |
| 8x8 | anonymous hidden | full+spl | yes | 4268 | 29 | 2 | - | 172 B | 3108 | 3216 | 1227 | 30 | buffered |  |
| 8x8 | anonymous hidden | full+data | yes | 4694 | 22 | 2 | - | 598 B | 3770 | 3990 | 991 | 23 | buffered |  |
| 8x8 | anonymous hidden | full+reply | yes | 4581 | 22 | 2 | - | 485 B | 3657 | 3891 | 991 | 23 | buffered |  |
| 8x8 | anonymous hidden | full+2tree | yes | 3906 | 22 | 2 | - |  | 2981 | 3216 | 992 | 23 | inline |  |
| 8x8 | anonymous hidden | full+4credential-shared | yes | 3976 | 24 | 2 | - |  | 2985 | 3216 | 1058 | 25 | inline |  |
| 8x8 | anonymous hidden | full+4credential-disjoint | yes | 4072 | 27 | 2 | - |  | 2985 | 3216 | 1154 | 28 | inline |  |
| 8x8 | anonymous public owners | min | yes | 3367 | 15 | 1 | - |  | 2751 | 2988 | 683 | 16 | inline |  |
| 8x8 | anonymous public owners | full | yes | 4029 | 26 | 3 | 1 |  | 2912 | 3115 | 1184 | 27 | inline |  |
| 8x8 | anonymous public owners | full+spl | yes | 4397 | 33 | 3 | - | 301 B | 3044 | 3119 | 1420 | 34 | buffered |  |
| 8x8 | anonymous public owners | full+data | yes | 4823 | 26 | 3 | - | 727 B | 3706 | 3893 | 1184 | 27 | buffered |  |
| 8x8 | anonymous public owners | full+reply | yes | 4710 | 26 | 3 | - | 614 B | 3593 | 3794 | 1184 | 27 | buffered |  |
| 8x8 | anonymous public owners | full+2tree | yes | 4035 | 26 | 3 | - |  | 2917 | 3119 | 1185 | 27 | inline |  |
| 8x8 | anonymous public owners | full+4credential-shared | yes | 4105 | 28 | 3 | - | 9 B | 2921 | 3119 | 1251 | 29 | buffered |  |
| 8x8 | anonymous public owners | full+4credential-disjoint | yes | 4201 | 31 | 3 | - | 105 B | 2921 | 3119 | 1347 | 32 | buffered |  |
| 8x8 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x16 | confidential signer | min | yes | 4809 | 15 | 1 | - | 713 B | 4193 | 4718 | 683 | 16 | buffered |  |
| 8x16 | confidential signer | full | yes | 5399 | 26 | 3 | none | 1303 B | 4282 | 4763 | 1184 | 27 | buffered |  |
| 8x16 | confidential signer | full+spl | yes | 5767 | 33 | 3 | - | 1671 B | 4414 | 4767 | 1420 | 34 | buffered |  |
| 8x16 | confidential signer | full+data | yes | 6985 | 26 | 3 | - | 2889 B | 5868 | 6317 | 1184 | 27 | buffered |  |
| 8x16 | confidential signer | full+reply | yes | 5399 | 26 | 3 | - | 1303 B | 4282 | 4763 | 1184 | 27 | buffered |  |
| 8x16 | confidential signer | full+2tree | yes | 5405 | 26 | 3 | - | 1309 B | 4287 | 4767 | 1185 | 27 | buffered |  |
| 8x16 | confidential signer | full+4credential-shared | yes | 5475 | 28 | 3 | - | 1379 B | 4291 | 4767 | 1251 | 29 | buffered |  |
| 8x16 | confidential signer | full+4credential-disjoint | yes | 5571 | 31 | 3 | - | 1475 B | 4291 | 4767 | 1347 | 32 | buffered |  |
| 8x16 | confidential in-proof | min | yes | 4904 | 15 | 1 | - | 808 B | 4289 | 4815 | 682 | 16 | buffered |  |
| 8x16 | confidential in-proof | full | yes | 5398 | 25 | 2 | none | 1302 B | 4378 | 4860 | 1087 | 26 | buffered |  |
| 8x16 | confidential in-proof | full+spl | yes | 5766 | 32 | 2 | - | 1670 B | 4510 | 4864 | 1323 | 33 | buffered |  |
| 8x16 | confidential in-proof | full+data | yes | 6984 | 25 | 2 | - | 2888 B | 5964 | 6414 | 1087 | 26 | buffered |  |
| 8x16 | confidential in-proof | full+reply | yes | 5398 | 25 | 2 | - | 1302 B | 4378 | 4860 | 1087 | 26 | buffered |  |
| 8x16 | confidential in-proof | full+2tree | yes | 5404 | 25 | 2 | - | 1308 B | 4383 | 4864 | 1088 | 26 | buffered |  |
| 8x16 | confidential in-proof | full+4credential-shared | yes | 5474 | 27 | 2 | - | 1378 B | 4387 | 4864 | 1154 | 28 | buffered |  |
| 8x16 | confidential in-proof | full+4credential-disjoint | yes | 5570 | 30 | 2 | - | 1474 B | 4387 | 4864 | 1250 | 31 | buffered |  |
| 8x16 | anonymous hidden | min | yes | 5424 | 15 | 1 | - | 1328 B | 4809 | 5365 | 682 | 16 | buffered |  |
| 8x16 | anonymous hidden | full | yes | 5894 | 22 | 2 | none | 1798 B | 4970 | 5492 | 991 | 23 | buffered |  |
| 8x16 | anonymous hidden | full+spl | yes | 6262 | 29 | 2 | - | 2166 B | 5102 | 5496 | 1227 | 30 | buffered |  |
| 8x16 | anonymous hidden | full+data | yes | 7480 | 22 | 2 | - | 3384 B | 6556 | 7046 | 991 | 23 | buffered |  |
| 8x16 | anonymous hidden | full+reply | yes | 7351 | 22 | 2 | - | 3255 B | 6427 | 6947 | 991 | 23 | buffered |  |
| 8x16 | anonymous hidden | full+2tree | yes | 5900 | 22 | 2 | - | 1804 B | 4975 | 5496 | 992 | 23 | buffered |  |
| 8x16 | anonymous hidden | full+4credential-shared | yes | 5970 | 24 | 2 | - | 1874 B | 4979 | 5496 | 1058 | 25 | buffered |  |
| 8x16 | anonymous hidden | full+4credential-disjoint | yes | 6066 | 27 | 2 | - | 1970 B | 4979 | 5496 | 1154 | 28 | buffered |  |
| 8x16 | anonymous public owners | min | yes | 5361 | 15 | 1 | - | 1265 B | 4745 | 5268 | 683 | 16 | buffered |  |
| 8x16 | anonymous public owners | full | yes | 6023 | 26 | 3 | none | 1927 B | 4906 | 5395 | 1184 | 27 | buffered |  |
| 8x16 | anonymous public owners | full+spl | yes | 6391 | 33 | 3 | - | 2295 B | 5038 | 5399 | 1420 | 34 | buffered |  |
| 8x16 | anonymous public owners | full+data | yes | 7609 | 26 | 3 | - | 3513 B | 6492 | 6949 | 1184 | 27 | buffered |  |
| 8x16 | anonymous public owners | full+reply | yes | 7480 | 26 | 3 | - | 3384 B | 6363 | 6850 | 1184 | 27 | buffered |  |
| 8x16 | anonymous public owners | full+2tree | yes | 6029 | 26 | 3 | - | 1933 B | 4911 | 5399 | 1185 | 27 | buffered |  |
| 8x16 | anonymous public owners | full+4credential-shared | yes | 6099 | 28 | 3 | - | 2003 B | 4915 | 5399 | 1251 | 29 | buffered |  |
| 8x16 | anonymous public owners | full+4credential-disjoint | yes | 6195 | 31 | 3 | - | 2099 B | 4915 | 5399 | 1347 | 32 | buffered |  |
| 8x16 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 8x16 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x16 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 12x2 | confidential signer | min | yes | 2029 | 19 | 1 | - |  | 1281 | 1308 | 815 | 20 | inline |  |
| 12x2 | confidential signer | full | yes | 2619 | 30 | 3 | 10 |  | 1370 | 1353 | 1316 | 31 | inline |  |
| 12x2 | confidential signer | full+spl | yes | 2987 | 37 | 3 | - |  | 1502 | 1357 | 1552 | 38 | inline |  |
| 12x2 | confidential signer | full+data | yes | 2819 | 30 | 3 | - |  | 1570 | 1549 | 1316 | 31 | inline |  |
| 12x2 | confidential signer | full+reply | yes | 2619 | 30 | 3 | - |  | 1370 | 1353 | 1316 | 31 | inline |  |
| 12x2 | confidential signer | full+2tree | yes | 2626 | 30 | 3 | - |  | 1376 | 1357 | 1317 | 31 | inline |  |
| 12x2 | confidential signer | full+4credential-shared | yes | 2696 | 32 | 3 | - |  | 1380 | 1357 | 1383 | 33 | inline |  |
| 12x2 | confidential signer | full+4credential-disjoint | yes | 2792 | 35 | 3 | - |  | 1380 | 1357 | 1479 | 36 | inline |  |
| 12x2 | confidential in-proof | min | yes | 2124 | 19 | 1 | - |  | 1377 | 1405 | 814 | 20 | inline |  |
| 12x2 | confidential in-proof | full | yes | 2618 | 29 | 2 | 10 |  | 1466 | 1450 | 1219 | 30 | inline |  |
| 12x2 | confidential in-proof | full+spl | yes | 2986 | 36 | 2 | - |  | 1598 | 1454 | 1455 | 37 | inline |  |
| 12x2 | confidential in-proof | full+data | yes | 2818 | 29 | 2 | - |  | 1666 | 1646 | 1219 | 30 | inline |  |
| 12x2 | confidential in-proof | full+reply | yes | 2618 | 29 | 2 | - |  | 1466 | 1450 | 1219 | 30 | inline |  |
| 12x2 | confidential in-proof | full+2tree | yes | 2625 | 29 | 2 | - |  | 1472 | 1454 | 1220 | 30 | inline |  |
| 12x2 | confidential in-proof | full+4credential-shared | yes | 2695 | 31 | 2 | - |  | 1476 | 1454 | 1286 | 32 | inline |  |
| 12x2 | confidential in-proof | full+4credential-disjoint | yes | 2791 | 34 | 2 | - |  | 1476 | 1454 | 1382 | 35 | inline |  |
| 12x2 | anonymous hidden | min | yes | 2196 | 19 | 1 | - |  | 1449 | 1507 | 814 | 20 | inline |  |
| 12x2 | anonymous hidden | full | yes | 2666 | 26 | 2 | 10 |  | 1610 | 1634 | 1123 | 27 | inline |  |
| 12x2 | anonymous hidden | full+spl | yes | 3034 | 33 | 2 | - |  | 1742 | 1638 | 1359 | 34 | inline |  |
| 12x2 | anonymous hidden | full+data | yes | 2866 | 26 | 2 | - |  | 1810 | 1830 | 1123 | 27 | inline |  |
| 12x2 | anonymous hidden | full+reply | yes | 2765 | 26 | 2 | - |  | 1709 | 1731 | 1123 | 27 | inline |  |
| 12x2 | anonymous hidden | full+2tree | yes | 2673 | 26 | 2 | - |  | 1616 | 1638 | 1124 | 27 | inline |  |
| 12x2 | anonymous hidden | full+4credential-shared | yes | 2743 | 28 | 2 | - |  | 1620 | 1638 | 1190 | 29 | inline |  |
| 12x2 | anonymous hidden | full+4credential-disjoint | yes | 2839 | 31 | 2 | - |  | 1620 | 1638 | 1286 | 32 | inline |  |
| 12x2 | anonymous public owners | min | yes | 2133 | 19 | 1 | - |  | 1385 | 1410 | 815 | 20 | inline |  |
| 12x2 | anonymous public owners | full | yes | 2795 | 30 | 3 | 10 |  | 1546 | 1537 | 1316 | 31 | inline |  |
| 12x2 | anonymous public owners | full+spl | yes | 3163 | 37 | 3 | - |  | 1678 | 1541 | 1552 | 38 | inline |  |
| 12x2 | anonymous public owners | full+data | yes | 2995 | 30 | 3 | - |  | 1746 | 1733 | 1316 | 31 | inline |  |
| 12x2 | anonymous public owners | full+reply | yes | 2894 | 30 | 3 | - |  | 1645 | 1634 | 1316 | 31 | inline |  |
| 12x2 | anonymous public owners | full+2tree | yes | 2802 | 30 | 3 | - |  | 1552 | 1541 | 1317 | 31 | inline |  |
| 12x2 | anonymous public owners | full+4credential-shared | yes | 2872 | 32 | 3 | - |  | 1556 | 1541 | 1383 | 33 | inline |  |
| 12x2 | anonymous public owners | full+4credential-disjoint | yes | 2968 | 35 | 3 | - |  | 1556 | 1541 | 1479 | 36 | inline |  |
| 12x2 | confidential entry | min | yes | 4437 | 19 | 1 | - | 341 B | 3689 | 3716 | 815 | 20 | buffered |  |
| 12x2 | confidential entry | full | yes | 5027 | 30 | 3 | none | 931 B | 3778 | 3761 | 1316 | 31 | buffered |  |
| 12x2 | confidential entry | full+spl | yes | 5395 | 37 | 3 | - | 1299 B | 3910 | 3765 | 1552 | 38 | buffered |  |
| 12x2 | confidential entry | full+data | yes | 5227 | 30 | 3 | - | 1131 B | 3978 | 3957 | 1316 | 31 | buffered |  |
| 12x2 | confidential entry | full+reply | yes | 5027 | 30 | 3 | - | 931 B | 3778 | 3761 | 1316 | 31 | buffered |  |
| 12x2 | confidential entry | full+2tree | yes | 5034 | 30 | 3 | - | 938 B | 3784 | 3765 | 1317 | 31 | buffered |  |
| 12x2 | confidential entry | full+4credential-shared | yes | 5104 | 32 | 3 | - | 1008 B | 3788 | 3765 | 1383 | 33 | buffered |  |
| 12x2 | confidential entry | full+4credential-disjoint | yes | 5200 | 35 | 3 | - | 1104 B | 3788 | 3765 | 1479 | 36 | buffered |  |
| 12x2 | anonymous entry | min | yes | 4636 | 19 | 1 | - | 540 B | 3889 | 3915 | 814 | 20 | buffered |  |
| 12x2 | anonymous entry | full | yes | 5106 | 26 | 2 | none | 1010 B | 4050 | 4042 | 1123 | 27 | buffered |  |
| 12x2 | anonymous entry | full+spl | yes | 5474 | 33 | 2 | - | 1378 B | 4182 | 4046 | 1359 | 34 | buffered |  |
| 12x2 | anonymous entry | full+data | yes | 5306 | 26 | 2 | - | 1210 B | 4250 | 4238 | 1123 | 27 | buffered |  |
| 12x2 | anonymous entry | full+reply | yes | 5205 | 26 | 2 | - | 1109 B | 4149 | 4139 | 1123 | 27 | buffered |  |
| 12x2 | anonymous entry | full+2tree | yes | 5113 | 26 | 2 | - | 1017 B | 4056 | 4046 | 1124 | 27 | buffered |  |
| 12x2 | anonymous entry | full+4credential-shared | yes | 5183 | 28 | 2 | - | 1087 B | 4060 | 4046 | 1190 | 29 | buffered |  |
| 12x2 | anonymous entry | full+4credential-disjoint | yes | 5279 | 31 | 2 | - | 1183 B | 4060 | 4046 | 1286 | 32 | buffered |  |
| 12x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 12x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 12x4 | confidential signer | min | yes | 2463 | 19 | 1 | - |  | 1715 | 1814 | 815 | 20 | inline |  |
| 12x4 | confidential signer | full | yes | 3053 | 30 | 3 | 10 |  | 1804 | 1859 | 1316 | 31 | inline |  |
| 12x4 | confidential signer | full+spl | yes | 3421 | 37 | 3 | - |  | 1936 | 1863 | 1552 | 38 | inline |  |
| 12x4 | confidential signer | full+data | yes | 3451 | 30 | 3 | - |  | 2202 | 2249 | 1316 | 31 | inline |  |
| 12x4 | confidential signer | full+reply | yes | 3053 | 30 | 3 | - |  | 1804 | 1859 | 1316 | 31 | inline |  |
| 12x4 | confidential signer | full+2tree | yes | 3060 | 30 | 3 | - |  | 1810 | 1863 | 1317 | 31 | inline |  |
| 12x4 | confidential signer | full+4credential-shared | yes | 3130 | 32 | 3 | - |  | 1814 | 1863 | 1383 | 33 | inline |  |
| 12x4 | confidential signer | full+4credential-disjoint | yes | 3226 | 35 | 3 | - |  | 1814 | 1863 | 1479 | 36 | inline |  |
| 12x4 | confidential in-proof | min | yes | 2558 | 19 | 1 | - |  | 1811 | 1911 | 814 | 20 | inline |  |
| 12x4 | confidential in-proof | full | yes | 3052 | 29 | 2 | 10 |  | 1900 | 1956 | 1219 | 30 | inline |  |
| 12x4 | confidential in-proof | full+spl | yes | 3420 | 36 | 2 | - |  | 2032 | 1960 | 1455 | 37 | inline |  |
| 12x4 | confidential in-proof | full+data | yes | 3450 | 29 | 2 | - |  | 2298 | 2346 | 1219 | 30 | inline |  |
| 12x4 | confidential in-proof | full+reply | yes | 3052 | 29 | 2 | - |  | 1900 | 1956 | 1219 | 30 | inline |  |
| 12x4 | confidential in-proof | full+2tree | yes | 3059 | 29 | 2 | - |  | 1906 | 1960 | 1220 | 30 | inline |  |
| 12x4 | confidential in-proof | full+4credential-shared | yes | 3129 | 31 | 2 | - |  | 1910 | 1960 | 1286 | 32 | inline |  |
| 12x4 | confidential in-proof | full+4credential-disjoint | yes | 3225 | 34 | 2 | - |  | 1910 | 1960 | 1382 | 35 | inline |  |
| 12x4 | anonymous hidden | min | yes | 2694 | 19 | 1 | - |  | 1947 | 2077 | 814 | 20 | inline |  |
| 12x4 | anonymous hidden | full | yes | 3164 | 26 | 2 | 9 |  | 2108 | 2204 | 1123 | 27 | inline |  |
| 12x4 | anonymous hidden | full+spl | yes | 3532 | 33 | 2 | - |  | 2240 | 2208 | 1359 | 34 | inline |  |
| 12x4 | anonymous hidden | full+data | yes | 3562 | 26 | 2 | - |  | 2506 | 2594 | 1123 | 27 | inline |  |
| 12x4 | anonymous hidden | full+reply | yes | 3457 | 26 | 2 | - |  | 2401 | 2495 | 1123 | 27 | inline |  |
| 12x4 | anonymous hidden | full+2tree | yes | 3171 | 26 | 2 | - |  | 2114 | 2208 | 1124 | 27 | inline |  |
| 12x4 | anonymous hidden | full+4credential-shared | yes | 3241 | 28 | 2 | - |  | 2118 | 2208 | 1190 | 29 | inline |  |
| 12x4 | anonymous hidden | full+4credential-disjoint | yes | 3337 | 31 | 2 | - |  | 2118 | 2208 | 1286 | 32 | inline |  |
| 12x4 | anonymous public owners | min | yes | 2631 | 19 | 1 | - |  | 1883 | 1980 | 815 | 20 | inline |  |
| 12x4 | anonymous public owners | full | yes | 3293 | 30 | 3 | 9 |  | 2044 | 2107 | 1316 | 31 | inline |  |
| 12x4 | anonymous public owners | full+spl | yes | 3661 | 37 | 3 | - |  | 2176 | 2111 | 1552 | 38 | inline |  |
| 12x4 | anonymous public owners | full+data | yes | 3691 | 30 | 3 | - |  | 2442 | 2497 | 1316 | 31 | inline |  |
| 12x4 | anonymous public owners | full+reply | yes | 3586 | 30 | 3 | - |  | 2337 | 2398 | 1316 | 31 | inline |  |
| 12x4 | anonymous public owners | full+2tree | yes | 3300 | 30 | 3 | - |  | 2050 | 2111 | 1317 | 31 | inline |  |
| 12x4 | anonymous public owners | full+4credential-shared | yes | 3370 | 32 | 3 | - |  | 2054 | 2111 | 1383 | 33 | inline |  |
| 12x4 | anonymous public owners | full+4credential-disjoint | yes | 3466 | 35 | 3 | - |  | 2054 | 2111 | 1479 | 36 | inline |  |
| 12x4 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 12x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 12x8 | confidential signer | min | yes | 3331 | 19 | 1 | - |  | 2583 | 2826 | 815 | 20 | inline |  |
| 12x8 | confidential signer | full | yes | 3921 | 30 | 3 | 2 |  | 2672 | 2871 | 1316 | 31 | inline |  |
| 12x8 | confidential signer | full+spl | yes | 4289 | 37 | 3 | - | 193 B | 2804 | 2875 | 1552 | 38 | buffered |  |
| 12x8 | confidential signer | full+data | yes | 4715 | 30 | 3 | - | 619 B | 3466 | 3649 | 1316 | 31 | buffered |  |
| 12x8 | confidential signer | full+reply | yes | 3921 | 30 | 3 | - |  | 2672 | 2871 | 1316 | 31 | inline |  |
| 12x8 | confidential signer | full+2tree | yes | 3928 | 30 | 3 | - |  | 2678 | 2875 | 1317 | 31 | inline |  |
| 12x8 | confidential signer | full+4credential-shared | yes | 3998 | 32 | 3 | - |  | 2682 | 2875 | 1383 | 33 | inline |  |
| 12x8 | confidential signer | full+4credential-disjoint | yes | 4094 | 35 | 3 | - |  | 2682 | 2875 | 1479 | 36 | inline |  |
| 12x8 | confidential in-proof | min | yes | 3426 | 19 | 1 | - |  | 2679 | 2923 | 814 | 20 | inline |  |
| 12x8 | confidential in-proof | full | yes | 3920 | 29 | 2 | 1 |  | 2768 | 2968 | 1219 | 30 | inline |  |
| 12x8 | confidential in-proof | full+spl | yes | 4288 | 36 | 2 | - | 192 B | 2900 | 2972 | 1455 | 37 | buffered |  |
| 12x8 | confidential in-proof | full+data | yes | 4714 | 29 | 2 | - | 618 B | 3562 | 3746 | 1219 | 30 | buffered |  |
| 12x8 | confidential in-proof | full+reply | yes | 3920 | 29 | 2 | - |  | 2768 | 2968 | 1219 | 30 | inline |  |
| 12x8 | confidential in-proof | full+2tree | yes | 3927 | 29 | 2 | - |  | 2774 | 2972 | 1220 | 30 | inline |  |
| 12x8 | confidential in-proof | full+4credential-shared | yes | 3997 | 31 | 2 | - |  | 2778 | 2972 | 1286 | 32 | inline |  |
| 12x8 | confidential in-proof | full+4credential-disjoint | yes | 4093 | 34 | 2 | - |  | 2778 | 2972 | 1382 | 35 | inline |  |
| 12x8 | anonymous hidden | min | yes | 3690 | 19 | 1 | - |  | 2943 | 3217 | 814 | 20 | inline |  |
| 12x8 | anonymous hidden | full | yes | 4160 | 26 | 2 | none | 64 B | 3104 | 3344 | 1123 | 27 | buffered |  |
| 12x8 | anonymous hidden | full+spl | yes | 4528 | 33 | 2 | - | 432 B | 3236 | 3348 | 1359 | 34 | buffered |  |
| 12x8 | anonymous hidden | full+data | yes | 4954 | 26 | 2 | - | 858 B | 3898 | 4122 | 1123 | 27 | buffered |  |
| 12x8 | anonymous hidden | full+reply | yes | 4841 | 26 | 2 | - | 745 B | 3785 | 4023 | 1123 | 27 | buffered |  |
| 12x8 | anonymous hidden | full+2tree | yes | 4167 | 26 | 2 | - | 71 B | 3110 | 3348 | 1124 | 27 | buffered |  |
| 12x8 | anonymous hidden | full+4credential-shared | yes | 4237 | 28 | 2 | - | 141 B | 3114 | 3348 | 1190 | 29 | buffered |  |
| 12x8 | anonymous hidden | full+4credential-disjoint | yes | 4333 | 31 | 2 | - | 237 B | 3114 | 3348 | 1286 | 32 | buffered |  |
| 12x8 | anonymous public owners | min | yes | 3627 | 19 | 1 | - |  | 2879 | 3120 | 815 | 20 | inline |  |
| 12x8 | anonymous public owners | full | yes | 4289 | 30 | 3 | none | 193 B | 3040 | 3247 | 1316 | 31 | buffered |  |
| 12x8 | anonymous public owners | full+spl | yes | 4657 | 37 | 3 | - | 561 B | 3172 | 3251 | 1552 | 38 | buffered |  |
| 12x8 | anonymous public owners | full+data | yes | 5083 | 30 | 3 | - | 987 B | 3834 | 4025 | 1316 | 31 | buffered |  |
| 12x8 | anonymous public owners | full+reply | yes | 4970 | 30 | 3 | - | 874 B | 3721 | 3926 | 1316 | 31 | buffered |  |
| 12x8 | anonymous public owners | full+2tree | yes | 4296 | 30 | 3 | - | 200 B | 3046 | 3251 | 1317 | 31 | buffered |  |
| 12x8 | anonymous public owners | full+4credential-shared | yes | 4366 | 32 | 3 | - | 270 B | 3050 | 3251 | 1383 | 33 | buffered |  |
| 12x8 | anonymous public owners | full+4credential-disjoint | yes | 4462 | 35 | 3 | - | 366 B | 3050 | 3251 | 1479 | 36 | buffered |  |
| 12x8 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 12x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 12x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 16x2 | confidential signer | min | yes | 2289 | 23 | 1 | - |  | 1409 | 1440 | 947 | 24 | inline |  |
| 16x2 | confidential signer | full | yes | 2879 | 34 | 3 | 10 |  | 1498 | 1485 | 1448 | 35 | inline |  |
| 16x2 | confidential signer | full+spl | yes | 3247 | 41 | 3 | - |  | 1630 | 1489 | 1684 | 42 | inline |  |
| 16x2 | confidential signer | full+data | yes | 3079 | 34 | 3 | - |  | 1698 | 1681 | 1448 | 35 | inline |  |
| 16x2 | confidential signer | full+reply | yes | 2879 | 34 | 3 | - |  | 1498 | 1485 | 1448 | 35 | inline |  |
| 16x2 | confidential signer | full+2tree | yes | 2886 | 34 | 3 | - |  | 1504 | 1489 | 1449 | 35 | inline |  |
| 16x2 | confidential signer | full+4credential-shared | yes | 2956 | 36 | 3 | - |  | 1508 | 1489 | 1515 | 37 | inline |  |
| 16x2 | confidential signer | full+4credential-disjoint | yes | 3052 | 39 | 3 | - |  | 1508 | 1489 | 1611 | 40 | inline |  |
| 16x2 | confidential in-proof | min | yes | 2384 | 23 | 1 | - |  | 1505 | 1537 | 946 | 24 | inline |  |
| 16x2 | confidential in-proof | full | yes | 2878 | 33 | 2 | 10 |  | 1594 | 1582 | 1351 | 34 | inline |  |
| 16x2 | confidential in-proof | full+spl | yes | 3246 | 40 | 2 | - |  | 1726 | 1586 | 1587 | 41 | inline |  |
| 16x2 | confidential in-proof | full+data | yes | 3078 | 33 | 2 | - |  | 1794 | 1778 | 1351 | 34 | inline |  |
| 16x2 | confidential in-proof | full+reply | yes | 2878 | 33 | 2 | - |  | 1594 | 1582 | 1351 | 34 | inline |  |
| 16x2 | confidential in-proof | full+2tree | yes | 2885 | 33 | 2 | - |  | 1600 | 1586 | 1352 | 34 | inline |  |
| 16x2 | confidential in-proof | full+4credential-shared | yes | 2955 | 35 | 2 | - |  | 1604 | 1586 | 1418 | 36 | inline |  |
| 16x2 | confidential in-proof | full+4credential-disjoint | yes | 3051 | 38 | 2 | - |  | 1604 | 1586 | 1514 | 39 | inline |  |
| 16x2 | anonymous hidden | min | yes | 2456 | 23 | 1 | - |  | 1577 | 1639 | 946 | 24 | inline |  |
| 16x2 | anonymous hidden | full | yes | 2926 | 30 | 2 | 10 |  | 1738 | 1766 | 1255 | 31 | inline |  |
| 16x2 | anonymous hidden | full+spl | yes | 3294 | 37 | 2 | - |  | 1870 | 1770 | 1491 | 38 | inline |  |
| 16x2 | anonymous hidden | full+data | yes | 3126 | 30 | 2 | - |  | 1938 | 1962 | 1255 | 31 | inline |  |
| 16x2 | anonymous hidden | full+reply | yes | 3025 | 30 | 2 | - |  | 1837 | 1863 | 1255 | 31 | inline |  |
| 16x2 | anonymous hidden | full+2tree | yes | 2933 | 30 | 2 | - |  | 1744 | 1770 | 1256 | 31 | inline |  |
| 16x2 | anonymous hidden | full+4credential-shared | yes | 3003 | 32 | 2 | - |  | 1748 | 1770 | 1322 | 33 | inline |  |
| 16x2 | anonymous hidden | full+4credential-disjoint | yes | 3099 | 35 | 2 | - |  | 1748 | 1770 | 1418 | 36 | inline |  |
| 16x2 | anonymous public owners | min | yes | 2393 | 23 | 1 | - |  | 1513 | 1542 | 947 | 24 | inline |  |
| 16x2 | anonymous public owners | full | yes | 3055 | 34 | 3 | 10 |  | 1674 | 1669 | 1448 | 35 | inline |  |
| 16x2 | anonymous public owners | full+spl | yes | 3423 | 41 | 3 | - |  | 1806 | 1673 | 1684 | 42 | inline |  |
| 16x2 | anonymous public owners | full+data | yes | 3255 | 34 | 3 | - |  | 1874 | 1865 | 1448 | 35 | inline |  |
| 16x2 | anonymous public owners | full+reply | yes | 3154 | 34 | 3 | - |  | 1773 | 1766 | 1448 | 35 | inline |  |
| 16x2 | anonymous public owners | full+2tree | yes | 3062 | 34 | 3 | - |  | 1680 | 1673 | 1449 | 35 | inline |  |
| 16x2 | anonymous public owners | full+4credential-shared | yes | 3132 | 36 | 3 | - |  | 1684 | 1673 | 1515 | 37 | inline |  |
| 16x2 | anonymous public owners | full+4credential-disjoint | yes | 3228 | 39 | 3 | - |  | 1684 | 1673 | 1611 | 40 | inline |  |
| 16x2 | confidential entry | min | yes | 5497 | 23 | 1 | - | 1401 B | 4617 | 4648 | 947 | 24 | buffered |  |
| 16x2 | confidential entry | full | yes | 6087 | 34 | 3 | none | 1991 B | 4706 | 4693 | 1448 | 35 | buffered |  |
| 16x2 | confidential entry | full+spl | yes | 6455 | 41 | 3 | - | 2359 B | 4838 | 4697 | 1684 | 42 | buffered |  |
| 16x2 | confidential entry | full+data | yes | 6287 | 34 | 3 | - | 2191 B | 4906 | 4889 | 1448 | 35 | buffered |  |
| 16x2 | confidential entry | full+reply | yes | 6087 | 34 | 3 | - | 1991 B | 4706 | 4693 | 1448 | 35 | buffered |  |
| 16x2 | confidential entry | full+2tree | yes | 6094 | 34 | 3 | - | 1998 B | 4712 | 4697 | 1449 | 35 | buffered |  |
| 16x2 | confidential entry | full+4credential-shared | yes | 6164 | 36 | 3 | - | 2068 B | 4716 | 4697 | 1515 | 37 | buffered |  |
| 16x2 | confidential entry | full+4credential-disjoint | yes | 6260 | 39 | 3 | - | 2164 B | 4716 | 4697 | 1611 | 40 | buffered |  |
| 16x2 | anonymous entry | min | yes | 5696 | 23 | 1 | - | 1600 B | 4817 | 4847 | 946 | 24 | buffered |  |
| 16x2 | anonymous entry | full | yes | 6166 | 30 | 2 | none | 2070 B | 4978 | 4974 | 1255 | 31 | buffered |  |
| 16x2 | anonymous entry | full+spl | yes | 6534 | 37 | 2 | - | 2438 B | 5110 | 4978 | 1491 | 38 | buffered |  |
| 16x2 | anonymous entry | full+data | yes | 6366 | 30 | 2 | - | 2270 B | 5178 | 5170 | 1255 | 31 | buffered |  |
| 16x2 | anonymous entry | full+reply | yes | 6265 | 30 | 2 | - | 2169 B | 5077 | 5071 | 1255 | 31 | buffered |  |
| 16x2 | anonymous entry | full+2tree | yes | 6173 | 30 | 2 | - | 2077 B | 4984 | 4978 | 1256 | 31 | buffered |  |
| 16x2 | anonymous entry | full+4credential-shared | yes | 6243 | 32 | 2 | - | 2147 B | 4988 | 4978 | 1322 | 33 | buffered |  |
| 16x2 | anonymous entry | full+4credential-disjoint | yes | 6339 | 35 | 2 | - | 2243 B | 4988 | 4978 | 1418 | 36 | buffered |  |
| 16x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 16x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 16x4 | confidential signer | min | yes | 2723 | 23 | 1 | - |  | 1843 | 1946 | 947 | 24 | inline |  |
| 16x4 | confidential signer | full | yes | 3313 | 34 | 3 | 9 |  | 1932 | 1991 | 1448 | 35 | inline |  |
| 16x4 | confidential signer | full+spl | yes | 3681 | 41 | 3 | - |  | 2064 | 1995 | 1684 | 42 | inline |  |
| 16x4 | confidential signer | full+data | yes | 3711 | 34 | 3 | - |  | 2330 | 2381 | 1448 | 35 | inline |  |
| 16x4 | confidential signer | full+reply | yes | 3313 | 34 | 3 | - |  | 1932 | 1991 | 1448 | 35 | inline |  |
| 16x4 | confidential signer | full+2tree | yes | 3320 | 34 | 3 | - |  | 1938 | 1995 | 1449 | 35 | inline |  |
| 16x4 | confidential signer | full+4credential-shared | yes | 3390 | 36 | 3 | - |  | 1942 | 1995 | 1515 | 37 | inline |  |
| 16x4 | confidential signer | full+4credential-disjoint | yes | 3486 | 39 | 3 | - |  | 1942 | 1995 | 1611 | 40 | inline |  |
| 16x4 | confidential in-proof | min | yes | 2818 | 23 | 1 | - |  | 1939 | 2043 | 946 | 24 | inline |  |
| 16x4 | confidential in-proof | full | yes | 3312 | 33 | 2 | 8 |  | 2028 | 2088 | 1351 | 34 | inline |  |
| 16x4 | confidential in-proof | full+spl | yes | 3680 | 40 | 2 | - |  | 2160 | 2092 | 1587 | 41 | inline |  |
| 16x4 | confidential in-proof | full+data | yes | 3710 | 33 | 2 | - |  | 2426 | 2478 | 1351 | 34 | inline |  |
| 16x4 | confidential in-proof | full+reply | yes | 3312 | 33 | 2 | - |  | 2028 | 2088 | 1351 | 34 | inline |  |
| 16x4 | confidential in-proof | full+2tree | yes | 3319 | 33 | 2 | - |  | 2034 | 2092 | 1352 | 34 | inline |  |
| 16x4 | confidential in-proof | full+4credential-shared | yes | 3389 | 35 | 2 | - |  | 2038 | 2092 | 1418 | 36 | inline |  |
| 16x4 | confidential in-proof | full+4credential-disjoint | yes | 3485 | 38 | 2 | - |  | 2038 | 2092 | 1514 | 39 | inline |  |
| 16x4 | anonymous hidden | min | yes | 2954 | 23 | 1 | - |  | 2075 | 2209 | 946 | 24 | inline |  |
| 16x4 | anonymous hidden | full | yes | 3424 | 30 | 2 | 6 |  | 2236 | 2336 | 1255 | 31 | inline |  |
| 16x4 | anonymous hidden | full+spl | yes | 3792 | 37 | 2 | - |  | 2368 | 2340 | 1491 | 38 | inline |  |
| 16x4 | anonymous hidden | full+data | yes | 3822 | 30 | 2 | - |  | 2634 | 2726 | 1255 | 31 | inline |  |
| 16x4 | anonymous hidden | full+reply | yes | 3717 | 30 | 2 | - |  | 2529 | 2627 | 1255 | 31 | inline |  |
| 16x4 | anonymous hidden | full+2tree | yes | 3431 | 30 | 2 | - |  | 2242 | 2340 | 1256 | 31 | inline |  |
| 16x4 | anonymous hidden | full+4credential-shared | yes | 3501 | 32 | 2 | - |  | 2246 | 2340 | 1322 | 33 | inline |  |
| 16x4 | anonymous hidden | full+4credential-disjoint | yes | 3597 | 35 | 2 | - |  | 2246 | 2340 | 1418 | 36 | inline |  |
| 16x4 | anonymous public owners | min | yes | 2891 | 23 | 1 | - |  | 2011 | 2112 | 947 | 24 | inline |  |
| 16x4 | anonymous public owners | full | yes | 3553 | 34 | 3 | 6 |  | 2172 | 2239 | 1448 | 35 | inline |  |
| 16x4 | anonymous public owners | full+spl | yes | 3921 | 41 | 3 | - |  | 2304 | 2243 | 1684 | 42 | inline |  |
| 16x4 | anonymous public owners | full+data | yes | 3951 | 34 | 3 | - |  | 2570 | 2629 | 1448 | 35 | inline |  |
| 16x4 | anonymous public owners | full+reply | yes | 3846 | 34 | 3 | - |  | 2465 | 2530 | 1448 | 35 | inline |  |
| 16x4 | anonymous public owners | full+2tree | yes | 3560 | 34 | 3 | - |  | 2178 | 2243 | 1449 | 35 | inline |  |
| 16x4 | anonymous public owners | full+4credential-shared | yes | 3630 | 36 | 3 | - |  | 2182 | 2243 | 1515 | 37 | inline |  |
| 16x4 | anonymous public owners | full+4credential-disjoint | yes | 3726 | 39 | 3 | - |  | 2182 | 2243 | 1611 | 40 | inline |  |
| 16x4 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 16x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 16x8 | confidential signer | min | yes | 3591 | 23 | 1 | - |  | 2711 | 2958 | 947 | 24 | inline |  |
| 16x8 | confidential signer | full | yes | 4181 | 34 | 3 | none | 85 B | 2800 | 3003 | 1448 | 35 | buffered |  |
| 16x8 | confidential signer | full+spl | yes | 4549 | 41 | 3 | - | 453 B | 2932 | 3007 | 1684 | 42 | buffered |  |
| 16x8 | confidential signer | full+data | yes | 4975 | 34 | 3 | - | 879 B | 3594 | 3781 | 1448 | 35 | buffered |  |
| 16x8 | confidential signer | full+reply | yes | 4181 | 34 | 3 | - | 85 B | 2800 | 3003 | 1448 | 35 | buffered |  |
| 16x8 | confidential signer | full+2tree | yes | 4188 | 34 | 3 | - | 92 B | 2806 | 3007 | 1449 | 35 | buffered |  |
| 16x8 | confidential signer | full+4credential-shared | yes | 4258 | 36 | 3 | - | 162 B | 2810 | 3007 | 1515 | 37 | buffered |  |
| 16x8 | confidential signer | full+4credential-disjoint | yes | 4354 | 39 | 3 | - | 258 B | 2810 | 3007 | 1611 | 40 | buffered |  |
| 16x8 | confidential in-proof | min | yes | 3686 | 23 | 1 | - |  | 2807 | 3055 | 946 | 24 | inline |  |
| 16x8 | confidential in-proof | full | yes | 4180 | 33 | 2 | none | 84 B | 2896 | 3100 | 1351 | 34 | buffered |  |
| 16x8 | confidential in-proof | full+spl | yes | 4548 | 40 | 2 | - | 452 B | 3028 | 3104 | 1587 | 41 | buffered |  |
| 16x8 | confidential in-proof | full+data | yes | 4974 | 33 | 2 | - | 878 B | 3690 | 3878 | 1351 | 34 | buffered |  |
| 16x8 | confidential in-proof | full+reply | yes | 4180 | 33 | 2 | - | 84 B | 2896 | 3100 | 1351 | 34 | buffered |  |
| 16x8 | confidential in-proof | full+2tree | yes | 4187 | 33 | 2 | - | 91 B | 2902 | 3104 | 1352 | 34 | buffered |  |
| 16x8 | confidential in-proof | full+4credential-shared | yes | 4257 | 35 | 2 | - | 161 B | 2906 | 3104 | 1418 | 36 | buffered |  |
| 16x8 | confidential in-proof | full+4credential-disjoint | yes | 4353 | 38 | 2 | - | 257 B | 2906 | 3104 | 1514 | 39 | buffered |  |
| 16x8 | anonymous hidden | min | yes | 3950 | 23 | 1 | - |  | 3071 | 3349 | 946 | 24 | inline |  |
| 16x8 | anonymous hidden | full | yes | 4420 | 30 | 2 | none | 324 B | 3232 | 3476 | 1255 | 31 | buffered |  |
| 16x8 | anonymous hidden | full+spl | yes | 4788 | 37 | 2 | - | 692 B | 3364 | 3480 | 1491 | 38 | buffered |  |
| 16x8 | anonymous hidden | full+data | yes | 5214 | 30 | 2 | - | 1118 B | 4026 | 4254 | 1255 | 31 | buffered |  |
| 16x8 | anonymous hidden | full+reply | yes | 5101 | 30 | 2 | - | 1005 B | 3913 | 4155 | 1255 | 31 | buffered |  |
| 16x8 | anonymous hidden | full+2tree | yes | 4427 | 30 | 2 | - | 331 B | 3238 | 3480 | 1256 | 31 | buffered |  |
| 16x8 | anonymous hidden | full+4credential-shared | yes | 4497 | 32 | 2 | - | 401 B | 3242 | 3480 | 1322 | 33 | buffered |  |
| 16x8 | anonymous hidden | full+4credential-disjoint | yes | 4593 | 35 | 2 | - | 497 B | 3242 | 3480 | 1418 | 36 | buffered |  |
| 16x8 | anonymous public owners | min | yes | 3887 | 23 | 1 | - |  | 3007 | 3252 | 947 | 24 | inline |  |
| 16x8 | anonymous public owners | full | yes | 4549 | 34 | 3 | none | 453 B | 3168 | 3379 | 1448 | 35 | buffered |  |
| 16x8 | anonymous public owners | full+spl | yes | 4917 | 41 | 3 | - | 821 B | 3300 | 3383 | 1684 | 42 | buffered |  |
| 16x8 | anonymous public owners | full+data | yes | 5343 | 34 | 3 | - | 1247 B | 3962 | 4157 | 1448 | 35 | buffered |  |
| 16x8 | anonymous public owners | full+reply | yes | 5230 | 34 | 3 | - | 1134 B | 3849 | 4058 | 1448 | 35 | buffered |  |
| 16x8 | anonymous public owners | full+2tree | yes | 4556 | 34 | 3 | - | 460 B | 3174 | 3383 | 1449 | 35 | buffered |  |
| 16x8 | anonymous public owners | full+4credential-shared | yes | 4626 | 36 | 3 | - | 530 B | 3178 | 3383 | 1515 | 37 | buffered |  |
| 16x8 | anonymous public owners | full+4credential-disjoint | yes | 4722 | 39 | 3 | - | 626 B | 3178 | 3383 | 1611 | 40 | buffered |  |
| 16x8 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 16x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 16x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 24x2 | confidential signer | min | yes | 2809 | 31 | 1 | - |  | 1665 | 1704 | 1211 | 32 | inline |  |
| 24x2 | confidential signer | full | yes | 3399 | 42 | 3 | 8 |  | 1754 | 1749 | 1712 | 43 | inline |  |
| 24x2 | confidential signer | full+spl | yes | 3767 | 49 | 3 | - |  | 1886 | 1753 | 1948 | 50 | inline |  |
| 24x2 | confidential signer | full+data | yes | 3599 | 42 | 3 | - |  | 1954 | 1945 | 1712 | 43 | inline |  |
| 24x2 | confidential signer | full+reply | yes | 3399 | 42 | 3 | - |  | 1754 | 1749 | 1712 | 43 | inline |  |
| 24x2 | confidential signer | full+2tree | yes | 3407 | 42 | 3 | - |  | 1761 | 1753 | 1713 | 43 | inline |  |
| 24x2 | confidential signer | full+4credential-shared | yes | 3477 | 44 | 3 | - |  | 1765 | 1753 | 1779 | 45 | inline |  |
| 24x2 | confidential signer | full+4credential-disjoint | yes | 3573 | 47 | 3 | - |  | 1765 | 1753 | 1875 | 48 | inline |  |
| 24x2 | confidential in-proof | min | yes | 2904 | 31 | 1 | - |  | 1761 | 1801 | 1210 | 32 | inline |  |
| 24x2 | confidential in-proof | full | yes | 3398 | 41 | 2 | 7 |  | 1850 | 1846 | 1615 | 42 | inline |  |
| 24x2 | confidential in-proof | full+spl | yes | 3766 | 48 | 2 | - |  | 1982 | 1850 | 1851 | 49 | inline |  |
| 24x2 | confidential in-proof | full+data | yes | 3598 | 41 | 2 | - |  | 2050 | 2042 | 1615 | 42 | inline |  |
| 24x2 | confidential in-proof | full+reply | yes | 3398 | 41 | 2 | - |  | 1850 | 1846 | 1615 | 42 | inline |  |
| 24x2 | confidential in-proof | full+2tree | yes | 3406 | 41 | 2 | - |  | 1857 | 1850 | 1616 | 42 | inline |  |
| 24x2 | confidential in-proof | full+4credential-shared | yes | 3476 | 43 | 2 | - |  | 1861 | 1850 | 1682 | 44 | inline |  |
| 24x2 | confidential in-proof | full+4credential-disjoint | yes | 3572 | 46 | 2 | - |  | 1861 | 1850 | 1778 | 47 | inline |  |
| 24x2 | anonymous hidden | min | yes | 2976 | 31 | 1 | - |  | 1833 | 1903 | 1210 | 32 | inline |  |
| 24x2 | anonymous hidden | full | yes | 3446 | 38 | 2 | 6 |  | 1994 | 2030 | 1519 | 39 | inline |  |
| 24x2 | anonymous hidden | full+spl | yes | 3814 | 45 | 2 | - |  | 2126 | 2034 | 1755 | 46 | inline |  |
| 24x2 | anonymous hidden | full+data | yes | 3646 | 38 | 2 | - |  | 2194 | 2226 | 1519 | 39 | inline |  |
| 24x2 | anonymous hidden | full+reply | yes | 3545 | 38 | 2 | - |  | 2093 | 2127 | 1519 | 39 | inline |  |
| 24x2 | anonymous hidden | full+2tree | yes | 3454 | 38 | 2 | - |  | 2001 | 2034 | 1520 | 39 | inline |  |
| 24x2 | anonymous hidden | full+4credential-shared | yes | 3524 | 40 | 2 | - |  | 2005 | 2034 | 1586 | 41 | inline |  |
| 24x2 | anonymous hidden | full+4credential-disjoint | yes | 3620 | 43 | 2 | - |  | 2005 | 2034 | 1682 | 44 | inline |  |
| 24x2 | anonymous public owners | min | yes | 2913 | 31 | 1 | - |  | 1769 | 1806 | 1211 | 32 | inline |  |
| 24x2 | anonymous public owners | full | yes | 3575 | 42 | 3 | 6 |  | 1930 | 1933 | 1712 | 43 | inline |  |
| 24x2 | anonymous public owners | full+spl | yes | 3943 | 49 | 3 | - |  | 2062 | 1937 | 1948 | 50 | inline |  |
| 24x2 | anonymous public owners | full+data | yes | 3775 | 42 | 3 | - |  | 2130 | 2129 | 1712 | 43 | inline |  |
| 24x2 | anonymous public owners | full+reply | yes | 3674 | 42 | 3 | - |  | 2029 | 2030 | 1712 | 43 | inline |  |
| 24x2 | anonymous public owners | full+2tree | yes | 3583 | 42 | 3 | - |  | 1937 | 1937 | 1713 | 43 | inline |  |
| 24x2 | anonymous public owners | full+4credential-shared | yes | 3653 | 44 | 3 | - |  | 1941 | 1937 | 1779 | 45 | inline |  |
| 24x2 | anonymous public owners | full+4credential-disjoint | yes | 3749 | 47 | 3 | - |  | 1941 | 1937 | 1875 | 48 | inline |  |
| 24x2 | confidential entry | min | yes | 7617 | 31 | 1 | - | 3521 B | 6473 | 6512 | 1211 | 32 | buffered |  |
| 24x2 | confidential entry | full | yes | 8207 | 42 | 3 | none | 4111 B | 6562 | 6557 | 1712 | 43 | buffered |  |
| 24x2 | confidential entry | full+spl | yes | 8575 | 49 | 3 | - | 4479 B | 6694 | 6561 | 1948 | 50 | buffered |  |
| 24x2 | confidential entry | full+data | yes | 8407 | 42 | 3 | - | 4311 B | 6762 | 6753 | 1712 | 43 | buffered |  |
| 24x2 | confidential entry | full+reply | yes | 8207 | 42 | 3 | - | 4111 B | 6562 | 6557 | 1712 | 43 | buffered |  |
| 24x2 | confidential entry | full+2tree | yes | 8215 | 42 | 3 | - | 4119 B | 6569 | 6561 | 1713 | 43 | buffered |  |
| 24x2 | confidential entry | full+4credential-shared | yes | 8285 | 44 | 3 | - | 4189 B | 6573 | 6561 | 1779 | 45 | buffered |  |
| 24x2 | confidential entry | full+4credential-disjoint | yes | 8381 | 47 | 3 | - | 4285 B | 6573 | 6561 | 1875 | 48 | buffered |  |
| 24x2 | anonymous entry | min | yes | 7816 | 31 | 1 | - | 3720 B | 6673 | 6711 | 1210 | 32 | buffered |  |
| 24x2 | anonymous entry | full | yes | 8286 | 38 | 2 | none | 4190 B | 6834 | 6838 | 1519 | 39 | buffered |  |
| 24x2 | anonymous entry | full+spl | yes | 8654 | 45 | 2 | - | 4558 B | 6966 | 6842 | 1755 | 46 | buffered |  |
| 24x2 | anonymous entry | full+data | yes | 8486 | 38 | 2 | - | 4390 B | 7034 | 7034 | 1519 | 39 | buffered |  |
| 24x2 | anonymous entry | full+reply | yes | 8385 | 38 | 2 | - | 4289 B | 6933 | 6935 | 1519 | 39 | buffered |  |
| 24x2 | anonymous entry | full+2tree | yes | 8294 | 38 | 2 | - | 4198 B | 6841 | 6842 | 1520 | 39 | buffered |  |
| 24x2 | anonymous entry | full+4credential-shared | yes | 8364 | 40 | 2 | - | 4268 B | 6845 | 6842 | 1586 | 41 | buffered |  |
| 24x2 | anonymous entry | full+4credential-disjoint | yes | 8460 | 43 | 2 | - | 4364 B | 6845 | 6842 | 1682 | 44 | buffered |  |
| 24x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 24x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 24x4 | confidential signer | min | yes | 3243 | 31 | 1 | - |  | 2099 | 2210 | 1211 | 32 | inline |  |
| 24x4 | confidential signer | full | yes | 3833 | 42 | 3 | 3 |  | 2188 | 2255 | 1712 | 43 | inline |  |
| 24x4 | confidential signer | full+spl | yes | 4201 | 49 | 3 | - | 105 B | 2320 | 2259 | 1948 | 50 | buffered |  |
| 24x4 | confidential signer | full+data | yes | 4231 | 42 | 3 | - | 135 B | 2586 | 2645 | 1712 | 43 | buffered |  |
| 24x4 | confidential signer | full+reply | yes | 3833 | 42 | 3 | - |  | 2188 | 2255 | 1712 | 43 | inline |  |
| 24x4 | confidential signer | full+2tree | yes | 3841 | 42 | 3 | - |  | 2195 | 2259 | 1713 | 43 | inline |  |
| 24x4 | confidential signer | full+4credential-shared | yes | 3911 | 44 | 3 | - |  | 2199 | 2259 | 1779 | 45 | inline |  |
| 24x4 | confidential signer | full+4credential-disjoint | yes | 4007 | 47 | 3 | - |  | 2199 | 2259 | 1875 | 48 | inline |  |
| 24x4 | confidential in-proof | min | yes | 3338 | 31 | 1 | - |  | 2195 | 2307 | 1210 | 32 | inline |  |
| 24x4 | confidential in-proof | full | yes | 3832 | 41 | 2 | 2 |  | 2284 | 2352 | 1615 | 42 | inline |  |
| 24x4 | confidential in-proof | full+spl | yes | 4200 | 48 | 2 | - | 104 B | 2416 | 2356 | 1851 | 49 | buffered |  |
| 24x4 | confidential in-proof | full+data | yes | 4230 | 41 | 2 | - | 134 B | 2682 | 2742 | 1615 | 42 | buffered |  |
| 24x4 | confidential in-proof | full+reply | yes | 3832 | 41 | 2 | - |  | 2284 | 2352 | 1615 | 42 | inline |  |
| 24x4 | confidential in-proof | full+2tree | yes | 3840 | 41 | 2 | - |  | 2291 | 2356 | 1616 | 42 | inline |  |
| 24x4 | confidential in-proof | full+4credential-shared | yes | 3910 | 43 | 2 | - |  | 2295 | 2356 | 1682 | 44 | inline |  |
| 24x4 | confidential in-proof | full+4credential-disjoint | yes | 4006 | 46 | 2 | - |  | 2295 | 2356 | 1778 | 47 | inline |  |
| 24x4 | anonymous hidden | min | yes | 3474 | 31 | 1 | - |  | 2331 | 2473 | 1210 | 32 | inline |  |
| 24x4 | anonymous hidden | full | yes | 3944 | 38 | 2 | 1 |  | 2492 | 2600 | 1519 | 39 | inline |  |
| 24x4 | anonymous hidden | full+spl | yes | 4312 | 45 | 2 | - | 216 B | 2624 | 2604 | 1755 | 46 | buffered |  |
| 24x4 | anonymous hidden | full+data | yes | 4342 | 38 | 2 | - | 246 B | 2890 | 2990 | 1519 | 39 | buffered |  |
| 24x4 | anonymous hidden | full+reply | yes | 4237 | 38 | 2 | - | 141 B | 2785 | 2891 | 1519 | 39 | buffered |  |
| 24x4 | anonymous hidden | full+2tree | yes | 3952 | 38 | 2 | - |  | 2499 | 2604 | 1520 | 39 | inline |  |
| 24x4 | anonymous hidden | full+4credential-shared | yes | 4022 | 40 | 2 | - |  | 2503 | 2604 | 1586 | 41 | inline |  |
| 24x4 | anonymous hidden | full+4credential-disjoint | yes | 4118 | 43 | 2 | - | 22 B | 2503 | 2604 | 1682 | 44 | buffered |  |
| 24x4 | anonymous public owners | min | yes | 3411 | 31 | 1 | - |  | 2267 | 2376 | 1211 | 32 | inline |  |
| 24x4 | anonymous public owners | full | yes | 4073 | 42 | 3 | 1 |  | 2428 | 2503 | 1712 | 43 | inline |  |
| 24x4 | anonymous public owners | full+spl | yes | 4441 | 49 | 3 | - | 345 B | 2560 | 2507 | 1948 | 50 | buffered |  |
| 24x4 | anonymous public owners | full+data | yes | 4471 | 42 | 3 | - | 375 B | 2826 | 2893 | 1712 | 43 | buffered |  |
| 24x4 | anonymous public owners | full+reply | yes | 4366 | 42 | 3 | - | 270 B | 2721 | 2794 | 1712 | 43 | buffered |  |
| 24x4 | anonymous public owners | full+2tree | yes | 4081 | 42 | 3 | - |  | 2435 | 2507 | 1713 | 43 | inline |  |
| 24x4 | anonymous public owners | full+4credential-shared | yes | 4151 | 44 | 3 | - | 55 B | 2439 | 2507 | 1779 | 45 | buffered |  |
| 24x4 | anonymous public owners | full+4credential-disjoint | yes | 4247 | 47 | 3 | - | 151 B | 2439 | 2507 | 1875 | 48 | buffered |  |
| 24x4 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 24x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 24x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 32x2 | confidential signer | min | yes | 3329 | 39 | 1 | - |  | 1921 | 1968 | 1475 | 40 | inline |  |
| 32x2 | confidential signer | full | yes | 3919 | 50 | 3 | 2 |  | 2010 | 2013 | 1976 | 51 | inline |  |
| 32x2 | confidential signer | full+spl | yes | 4287 | 57 | 3 | - | 191 B | 2142 | 2017 | 2212 | 58 | buffered |  |
| 32x2 | confidential signer | full+data | yes | 4119 | 50 | 3 | - | 23 B | 2210 | 2209 | 1976 | 51 | buffered |  |
| 32x2 | confidential signer | full+reply | yes | 3919 | 50 | 3 | - |  | 2010 | 2013 | 1976 | 51 | inline |  |
| 32x2 | confidential signer | full+2tree | yes | 3928 | 50 | 3 | - |  | 2018 | 2017 | 1977 | 51 | inline |  |
| 32x2 | confidential signer | full+4credential-shared | yes | 3998 | 52 | 3 | - |  | 2022 | 2017 | 2043 | 53 | inline |  |
| 32x2 | confidential signer | full+4credential-disjoint | yes | 4094 | 55 | 3 | - |  | 2022 | 2017 | 2139 | 56 | inline |  |
| 32x2 | confidential in-proof | min | yes | 3424 | 39 | 1 | - |  | 2017 | 2065 | 1474 | 40 | inline |  |
| 32x2 | confidential in-proof | full | yes | 3918 | 49 | 2 | 1 |  | 2106 | 2110 | 1879 | 50 | inline |  |
| 32x2 | confidential in-proof | full+spl | yes | 4286 | 56 | 2 | - | 190 B | 2238 | 2114 | 2115 | 57 | buffered |  |
| 32x2 | confidential in-proof | full+data | yes | 4118 | 49 | 2 | - | 22 B | 2306 | 2306 | 1879 | 50 | buffered |  |
| 32x2 | confidential in-proof | full+reply | yes | 3918 | 49 | 2 | - |  | 2106 | 2110 | 1879 | 50 | inline |  |
| 32x2 | confidential in-proof | full+2tree | yes | 3927 | 49 | 2 | - |  | 2114 | 2114 | 1880 | 50 | inline |  |
| 32x2 | confidential in-proof | full+4credential-shared | yes | 3997 | 51 | 2 | - |  | 2118 | 2114 | 1946 | 52 | inline |  |
| 32x2 | confidential in-proof | full+4credential-disjoint | yes | 4093 | 54 | 2 | - |  | 2118 | 2114 | 2042 | 55 | inline |  |
| 32x2 | anonymous hidden | min | yes | 3496 | 39 | 1 | - |  | 2089 | 2167 | 1474 | 40 | inline |  |
| 32x2 | anonymous hidden | full | yes | 3966 | 46 | 2 | 1 |  | 2250 | 2294 | 1783 | 47 | inline |  |
| 32x2 | anonymous hidden | full+spl | yes | 4334 | 53 | 2 | - | 238 B | 2382 | 2298 | 2019 | 54 | buffered |  |
| 32x2 | anonymous hidden | full+data | yes | 4166 | 46 | 2 | - | 70 B | 2450 | 2490 | 1783 | 47 | buffered |  |
| 32x2 | anonymous hidden | full+reply | yes | 4065 | 46 | 2 | - |  | 2349 | 2391 | 1783 | 47 | inline |  |
| 32x2 | anonymous hidden | full+2tree | yes | 3975 | 46 | 2 | - |  | 2258 | 2298 | 1784 | 47 | inline |  |
| 32x2 | anonymous hidden | full+4credential-shared | yes | 4045 | 48 | 2 | - |  | 2262 | 2298 | 1850 | 49 | inline |  |
| 32x2 | anonymous hidden | full+4credential-disjoint | yes | 4141 | 51 | 2 | - | 45 B | 2262 | 2298 | 1946 | 52 | buffered |  |
| 32x2 | anonymous public owners | min | yes | 3433 | 39 | 1 | - |  | 2025 | 2070 | 1475 | 40 | inline |  |
| 32x2 | anonymous public owners | full | yes | 4095 | 50 | 3 | 1 |  | 2186 | 2197 | 1976 | 51 | inline |  |
| 32x2 | anonymous public owners | full+spl | yes | 4463 | 57 | 3 | - | 367 B | 2318 | 2201 | 2212 | 58 | buffered |  |
| 32x2 | anonymous public owners | full+data | yes | 4295 | 50 | 3 | - | 199 B | 2386 | 2393 | 1976 | 51 | buffered |  |
| 32x2 | anonymous public owners | full+reply | yes | 4194 | 50 | 3 | - | 98 B | 2285 | 2294 | 1976 | 51 | buffered |  |
| 32x2 | anonymous public owners | full+2tree | yes | 4104 | 50 | 3 | - | 8 B | 2194 | 2201 | 1977 | 51 | buffered |  |
| 32x2 | anonymous public owners | full+4credential-shared | yes | 4174 | 52 | 3 | - | 78 B | 2198 | 2201 | 2043 | 53 | buffered |  |
| 32x2 | anonymous public owners | full+4credential-disjoint | yes | 4270 | 55 | 3 | - | 174 B | 2198 | 2201 | 2139 | 56 | buffered |  |
| 32x2 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 32x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 32x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 40x2 | confidential signer | min | yes | 3849 | 47 | 1 | - |  | 2177 | 2232 | 1739 | 48 | inline |  |
| 40x2 | confidential signer | full | yes | 4439 | 58 | 3 | none | 343 B | 2266 | 2277 | 2240 | 59 | buffered |  |
| 40x2 | confidential signer | full+spl | yes | 4807 | 65 | 3 | - | 711 B, 1 accounts | 2398 | 2281 | 2476 | 66 | no | 2 accounts |
| 40x2 | confidential signer | full+data | yes | 4639 | 58 | 3 | - | 543 B | 2466 | 2473 | 2240 | 59 | buffered |  |
| 40x2 | confidential signer | full+reply | yes | 4439 | 58 | 3 | - | 343 B | 2266 | 2277 | 2240 | 59 | buffered |  |
| 40x2 | confidential signer | full+2tree | yes | 4449 | 58 | 3 | - | 353 B | 2275 | 2281 | 2241 | 59 | buffered |  |
| 40x2 | confidential signer | full+4credential-shared | yes | 4519 | 60 | 3 | - | 423 B | 2279 | 2281 | 2307 | 61 | buffered |  |
| 40x2 | confidential signer | full+4credential-disjoint | yes | 4615 | 63 | 3 | - | 519 B | 2279 | 2281 | 2403 | 64 | buffered |  |
| 40x2 | confidential in-proof | min | yes | 3944 | 47 | 1 | - |  | 2273 | 2329 | 1738 | 48 | inline |  |
| 40x2 | confidential in-proof | full | yes | 4438 | 57 | 2 | none | 342 B | 2362 | 2374 | 2143 | 58 | buffered |  |
| 40x2 | confidential in-proof | full+spl | yes | 4806 | 64 | 2 | - | 710 B | 2494 | 2378 | 2379 | 65 | no | 1 accounts |
| 40x2 | confidential in-proof | full+data | yes | 4638 | 57 | 2 | - | 542 B | 2562 | 2570 | 2143 | 58 | buffered |  |
| 40x2 | confidential in-proof | full+reply | yes | 4438 | 57 | 2 | - | 342 B | 2362 | 2374 | 2143 | 58 | buffered |  |
| 40x2 | confidential in-proof | full+2tree | yes | 4448 | 57 | 2 | - | 352 B | 2371 | 2378 | 2144 | 58 | buffered |  |
| 40x2 | confidential in-proof | full+4credential-shared | yes | 4518 | 59 | 2 | - | 422 B | 2375 | 2378 | 2210 | 60 | buffered |  |
| 40x2 | confidential in-proof | full+4credential-disjoint | yes | 4614 | 62 | 2 | - | 518 B | 2375 | 2378 | 2306 | 63 | buffered |  |
| 40x2 | anonymous hidden | min | yes | 4016 | 47 | 1 | - |  | 2345 | 2431 | 1738 | 48 | inline |  |
| 40x2 | anonymous hidden | full | yes | 4486 | 54 | 2 | none | 390 B | 2506 | 2558 | 2047 | 55 | buffered |  |
| 40x2 | anonymous hidden | full+spl | yes | 4854 | 61 | 2 | - | 758 B | 2638 | 2562 | 2283 | 62 | buffered |  |
| 40x2 | anonymous hidden | full+data | yes | 4686 | 54 | 2 | - | 590 B | 2706 | 2754 | 2047 | 55 | buffered |  |
| 40x2 | anonymous hidden | full+reply | yes | 4585 | 54 | 2 | - | 489 B | 2605 | 2655 | 2047 | 55 | buffered |  |
| 40x2 | anonymous hidden | full+2tree | yes | 4496 | 54 | 2 | - | 400 B | 2515 | 2562 | 2048 | 55 | buffered |  |
| 40x2 | anonymous hidden | full+4credential-shared | yes | 4566 | 56 | 2 | - | 470 B | 2519 | 2562 | 2114 | 57 | buffered |  |
| 40x2 | anonymous hidden | full+4credential-disjoint | yes | 4662 | 59 | 2 | - | 566 B | 2519 | 2562 | 2210 | 60 | buffered |  |
| 40x2 | anonymous public owners | min | yes | 3953 | 47 | 1 | - |  | 2281 | 2334 | 1739 | 48 | inline |  |
| 40x2 | anonymous public owners | full | yes | 4615 | 58 | 3 | none | 519 B | 2442 | 2461 | 2240 | 59 | buffered |  |
| 40x2 | anonymous public owners | full+spl | yes | 4983 | 65 | 3 | - | 887 B, 1 accounts | 2574 | 2465 | 2476 | 66 | no | 2 accounts |
| 40x2 | anonymous public owners | full+data | yes | 4815 | 58 | 3 | - | 719 B | 2642 | 2657 | 2240 | 59 | buffered |  |
| 40x2 | anonymous public owners | full+reply | yes | 4714 | 58 | 3 | - | 618 B | 2541 | 2558 | 2240 | 59 | buffered |  |
| 40x2 | anonymous public owners | full+2tree | yes | 4625 | 58 | 3 | - | 529 B | 2451 | 2465 | 2241 | 59 | buffered |  |
| 40x2 | anonymous public owners | full+4credential-shared | yes | 4695 | 60 | 3 | - | 599 B | 2455 | 2465 | 2307 | 61 | buffered |  |
| 40x2 | anonymous public owners | full+4credential-disjoint | yes | 4791 | 63 | 3 | - | 695 B | 2455 | 2465 | 2403 | 64 | buffered |  |
| 40x2 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 40x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 40x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 48x2 | confidential signer | min | yes | 4369 | 55 | 1 | - | 273 B | 2433 | 2496 | 2003 | 56 | buffered |  |
| 48x2 | confidential signer | full | yes | 4959 | 66 | 3 | none | 863 B, 2 accounts | 2522 | 2541 | 2504 | 67 | no | 3 accounts |
| 48x2 | confidential signer | full+spl | yes | 5327 | 73 | 3 | - | 1231 B, 9 accounts | 2654 | 2545 | 2740 | 74 | no | 10 accounts |
| 48x2 | confidential signer | full+data | yes | 5159 | 66 | 3 | - | 1063 B, 2 accounts | 2722 | 2737 | 2504 | 67 | no | 3 accounts |
| 48x2 | confidential signer | full+reply | yes | 4959 | 66 | 3 | - | 863 B, 2 accounts | 2522 | 2541 | 2504 | 67 | no | 3 accounts |
| 48x2 | confidential signer | full+2tree | yes | 4970 | 66 | 3 | - | 874 B, 2 accounts | 2532 | 2545 | 2505 | 67 | no | 3 accounts |
| 48x2 | confidential signer | full+4credential-shared | yes | 5040 | 68 | 3 | - | 944 B, 4 accounts | 2536 | 2545 | 2571 | 69 | no | 5 accounts |
| 48x2 | confidential signer | full+4credential-disjoint | yes | 5136 | 71 | 3 | - | 1040 B, 7 accounts | 2536 | 2545 | 2667 | 72 | no | 8 accounts |
| 48x2 | confidential in-proof | min | yes | 4464 | 55 | 1 | - | 368 B | 2529 | 2593 | 2002 | 56 | buffered |  |
| 48x2 | confidential in-proof | full | yes | 4958 | 65 | 2 | none | 862 B, 1 accounts | 2618 | 2638 | 2407 | 66 | no | 2 accounts |
| 48x2 | confidential in-proof | full+spl | yes | 5326 | 72 | 2 | - | 1230 B, 8 accounts | 2750 | 2642 | 2643 | 73 | no | 9 accounts |
| 48x2 | confidential in-proof | full+data | yes | 5158 | 65 | 2 | - | 1062 B, 1 accounts | 2818 | 2834 | 2407 | 66 | no | 2 accounts |
| 48x2 | confidential in-proof | full+reply | yes | 4958 | 65 | 2 | - | 862 B, 1 accounts | 2618 | 2638 | 2407 | 66 | no | 2 accounts |
| 48x2 | confidential in-proof | full+2tree | yes | 4969 | 65 | 2 | - | 873 B, 1 accounts | 2628 | 2642 | 2408 | 66 | no | 2 accounts |
| 48x2 | confidential in-proof | full+4credential-shared | yes | 5039 | 67 | 2 | - | 943 B, 3 accounts | 2632 | 2642 | 2474 | 68 | no | 4 accounts |
| 48x2 | confidential in-proof | full+4credential-disjoint | yes | 5135 | 70 | 2 | - | 1039 B, 6 accounts | 2632 | 2642 | 2570 | 71 | no | 7 accounts |
| 48x2 | anonymous hidden | min | yes | 4536 | 55 | 1 | - | 440 B | 2601 | 2695 | 2002 | 56 | buffered |  |
| 48x2 | anonymous hidden | full | yes | 5006 | 62 | 2 | none | 910 B | 2762 | 2822 | 2311 | 63 | buffered |  |
| 48x2 | anonymous hidden | full+spl | yes | 5374 | 69 | 2 | - | 1278 B, 5 accounts | 2894 | 2826 | 2547 | 70 | no | 6 accounts |
| 48x2 | anonymous hidden | full+data | yes | 5206 | 62 | 2 | - | 1110 B | 2962 | 3018 | 2311 | 63 | buffered |  |
| 48x2 | anonymous hidden | full+reply | yes | 5105 | 62 | 2 | - | 1009 B | 2861 | 2919 | 2311 | 63 | buffered |  |
| 48x2 | anonymous hidden | full+2tree | yes | 5017 | 62 | 2 | - | 921 B | 2772 | 2826 | 2312 | 63 | buffered |  |
| 48x2 | anonymous hidden | full+4credential-shared | yes | 5087 | 64 | 2 | - | 991 B | 2776 | 2826 | 2378 | 65 | no | 1 accounts |
| 48x2 | anonymous hidden | full+4credential-disjoint | yes | 5183 | 67 | 2 | - | 1087 B, 3 accounts | 2776 | 2826 | 2474 | 68 | no | 4 accounts |
| 48x2 | anonymous public owners | min | yes | 4473 | 55 | 1 | - | 377 B | 2537 | 2598 | 2003 | 56 | buffered |  |
| 48x2 | anonymous public owners | full | yes | 5135 | 66 | 3 | none | 1039 B, 2 accounts | 2698 | 2725 | 2504 | 67 | no | 3 accounts |
| 48x2 | anonymous public owners | full+spl | yes | 5503 | 73 | 3 | - | 1407 B, 9 accounts | 2830 | 2729 | 2740 | 74 | no | 10 accounts |
| 48x2 | anonymous public owners | full+data | yes | 5335 | 66 | 3 | - | 1239 B, 2 accounts | 2898 | 2921 | 2504 | 67 | no | 3 accounts |
| 48x2 | anonymous public owners | full+reply | yes | 5234 | 66 | 3 | - | 1138 B, 2 accounts | 2797 | 2822 | 2504 | 67 | no | 3 accounts |
| 48x2 | anonymous public owners | full+2tree | yes | 5146 | 66 | 3 | - | 1050 B, 2 accounts | 2708 | 2729 | 2505 | 67 | no | 3 accounts |
| 48x2 | anonymous public owners | full+4credential-shared | yes | 5216 | 68 | 3 | - | 1120 B, 4 accounts | 2712 | 2729 | 2571 | 69 | no | 5 accounts |
| 48x2 | anonymous public owners | full+4credential-disjoint | yes | 5312 | 71 | 3 | - | 1216 B, 7 accounts | 2712 | 2729 | 2667 | 72 | no | 8 accounts |
| 48x2 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 48x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 48x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 49x2 | confidential signer | min | yes | 4434 | 56 | 1 | - | 338 B | 2465 | 2529 | 2036 | 57 | buffered |  |
| 49x2 | confidential signer | full | yes | 5024 | 67 | 3 | none | 928 B, 3 accounts | 2554 | 2574 | 2537 | 68 | no | 4 accounts |
| 49x2 | confidential signer | full+spl | yes | 5392 | 74 | 3 | - | 1296 B, 10 accounts | 2686 | 2578 | 2773 | 75 | no | 11 accounts |
| 49x2 | confidential signer | full+data | yes | 5224 | 67 | 3 | - | 1128 B, 3 accounts | 2754 | 2770 | 2537 | 68 | no | 4 accounts |
| 49x2 | confidential signer | full+reply | yes | 5024 | 67 | 3 | - | 928 B, 3 accounts | 2554 | 2574 | 2537 | 68 | no | 4 accounts |
| 49x2 | confidential signer | full+2tree | yes | 5036 | 67 | 3 | - | 940 B, 3 accounts | 2565 | 2578 | 2538 | 68 | no | 4 accounts |
| 49x2 | confidential signer | full+4credential-shared | yes | 5106 | 69 | 3 | - | 1010 B, 5 accounts | 2569 | 2578 | 2604 | 70 | no | 6 accounts |
| 49x2 | confidential signer | full+4credential-disjoint | yes | 5202 | 72 | 3 | - | 1106 B, 8 accounts | 2569 | 2578 | 2700 | 73 | no | 9 accounts |
| 49x2 | confidential in-proof | min | yes | 4529 | 56 | 1 | - | 433 B | 2561 | 2626 | 2035 | 57 | buffered |  |
| 49x2 | confidential in-proof | full | yes | 5023 | 66 | 2 | none | 927 B, 2 accounts | 2650 | 2671 | 2440 | 67 | no | 3 accounts |
| 49x2 | confidential in-proof | full+spl | yes | 5391 | 73 | 2 | - | 1295 B, 9 accounts | 2782 | 2675 | 2676 | 74 | no | 10 accounts |
| 49x2 | confidential in-proof | full+data | yes | 5223 | 66 | 2 | - | 1127 B, 2 accounts | 2850 | 2867 | 2440 | 67 | no | 3 accounts |
| 49x2 | confidential in-proof | full+reply | yes | 5023 | 66 | 2 | - | 927 B, 2 accounts | 2650 | 2671 | 2440 | 67 | no | 3 accounts |
| 49x2 | confidential in-proof | full+2tree | yes | 5035 | 66 | 2 | - | 939 B, 2 accounts | 2661 | 2675 | 2441 | 67 | no | 3 accounts |
| 49x2 | confidential in-proof | full+4credential-shared | yes | 5105 | 68 | 2 | - | 1009 B, 4 accounts | 2665 | 2675 | 2507 | 69 | no | 5 accounts |
| 49x2 | confidential in-proof | full+4credential-disjoint | yes | 5201 | 71 | 2 | - | 1105 B, 7 accounts | 2665 | 2675 | 2603 | 72 | no | 8 accounts |
| 49x2 | anonymous hidden | min | yes | 4601 | 56 | 1 | - | 505 B | 2633 | 2728 | 2035 | 57 | buffered |  |
| 49x2 | anonymous hidden | full | yes | 5071 | 63 | 2 | none | 975 B | 2794 | 2855 | 2344 | 64 | buffered |  |
| 49x2 | anonymous hidden | full+spl | yes | 5439 | 70 | 2 | - | 1343 B, 6 accounts | 2926 | 2859 | 2580 | 71 | no | 7 accounts |
| 49x2 | anonymous hidden | full+data | yes | 5271 | 63 | 2 | - | 1175 B | 2994 | 3051 | 2344 | 64 | buffered |  |
| 49x2 | anonymous hidden | full+reply | yes | 5170 | 63 | 2 | - | 1074 B | 2893 | 2952 | 2344 | 64 | buffered |  |
| 49x2 | anonymous hidden | full+2tree | yes | 5083 | 63 | 2 | - | 987 B | 2805 | 2859 | 2345 | 64 | buffered |  |
| 49x2 | anonymous hidden | full+4credential-shared | yes | 5153 | 65 | 2 | - | 1057 B, 1 accounts | 2809 | 2859 | 2411 | 66 | no | 2 accounts |
| 49x2 | anonymous hidden | full+4credential-disjoint | yes | 5249 | 68 | 2 | - | 1153 B, 4 accounts | 2809 | 2859 | 2507 | 69 | no | 5 accounts |
| 49x2 | anonymous public owners | min | yes | 4538 | 56 | 1 | - | 442 B | 2569 | 2631 | 2036 | 57 | buffered |  |
| 49x2 | anonymous public owners | full | yes | 5200 | 67 | 3 | none | 1104 B, 3 accounts | 2730 | 2758 | 2537 | 68 | no | 4 accounts |
| 49x2 | anonymous public owners | full+spl | yes | 5568 | 74 | 3 | - | 1472 B, 10 accounts | 2862 | 2762 | 2773 | 75 | no | 11 accounts |
| 49x2 | anonymous public owners | full+data | yes | 5400 | 67 | 3 | - | 1304 B, 3 accounts | 2930 | 2954 | 2537 | 68 | no | 4 accounts |
| 49x2 | anonymous public owners | full+reply | yes | 5299 | 67 | 3 | - | 1203 B, 3 accounts | 2829 | 2855 | 2537 | 68 | no | 4 accounts |
| 49x2 | anonymous public owners | full+2tree | yes | 5212 | 67 | 3 | - | 1116 B, 3 accounts | 2741 | 2762 | 2538 | 68 | no | 4 accounts |
| 49x2 | anonymous public owners | full+4credential-shared | yes | 5282 | 69 | 3 | - | 1186 B, 5 accounts | 2745 | 2762 | 2604 | 70 | no | 6 accounts |
| 49x2 | anonymous public owners | full+4credential-disjoint | yes | 5378 | 72 | 3 | - | 1282 B, 8 accounts | 2745 | 2762 | 2700 | 73 | no | 9 accounts |
| 49x2 | confidential entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | min | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+data | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | - | - | - | no | catalog key |
| 49x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 49x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x1 | merge | ring | yes | 1603 | 15 | 1 | - |  | - | - | - | - | inline |  |
| 8x1 | merge | owner signed | yes | 1697 | 16 | 2 | - |  | - | - | - | - | inline |  |
| 24x1 | merge | ring | yes | 2643 | 31 | 1 | - |  | - | - | - | - | inline |  |
| 24x1 | merge | owner signed | yes | 2737 | 32 | 2 | - |  | - | - | - | - | inline |  |
| 52x1 | merge | ring | yes | 4463 | 59 | 1 | - | 367 B | - | - | - | - | no | 367 B |
| 52x1 | merge | owner signed | yes | 4557 | 60 | 2 | - | 461 B | - | - | - | - | no | 461 B |
| 0x1 | deposit | min | yes | 980 | 8 | 1 | - |  | - | - | - | - | inline |  |
| 0x1 | deposit | full | yes | 1251 | 14 | 2 | - |  | - | - | - | - | inline |  |
| 0x2 | deposit | min | yes | 1358 | 8 | 1 | - |  | - | - | - | - | inline |  |
| 0x2 | deposit | full | yes | 1664 | 15 | 2 | - |  | - | - | - | - | inline |  |
| 0x4 | deposit | min | yes | 2114 | 8 | 1 | - |  | - | - | - | - | inline |  |
| 0x4 | deposit | full | yes | 2490 | 17 | 2 | - |  | - | - | - | - | inline |  |
| 0x8 | deposit | min | yes | 3626 | 8 | 1 | - |  | - | - | - | - | inline |  |
| 0x8 | deposit | full | yes | 4142 | 21 | 2 | - | 46 B | - | - | - | - | no | 46 B |

Entry capacities at two outputs. Each row is the widest owner run any path clears at that leg count, rows = run + a hidden sender. A confidential leg names its own destination, a hidden sender's legs name one. over: what stops the next owner.
| shape | rail | load | legs | leg kind | owner run | rows | accounts | signatures | frame | SPP CPI | fits | over |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 12x2 | confidential entry | min | 0 | sol | 12 | 12 | 31 | 12 | 3689 | 3716 | buffered | inputs |
| 12x2 | confidential entry | min | 1 | sol | 12 | 12 | 33 | 12 | 3698 | 3725 | buffered | inputs |
| 12x2 | confidential entry | min | 4 | sol | 12 | 12 | 36 | 12 | 3725 | 3752 | buffered | inputs |
| 12x2 | confidential entry | min | 8 | sol | 12 | 12 | 40 | 12 | 3761 | 3788 | buffered | inputs |
| 12x2 | confidential entry | min | 12 | sol | 12 | 12 | 44 | 12 | 3797 | 3824 | buffered | inputs |
| 12x2 | confidential entry | min | 16 | sol | 12 | 12 | 48 | 12 | 3833 | 3860 | buffered | inputs |
| 12x2 | confidential entry | min | 20 | sol | 12 | 12 | 52 | 12 | 3869 | 3896 | buffered | inputs |
| 12x2 | confidential entry | min | 24 | sol | 12 | 12 | 56 | 12 | 3905 | 3932 | buffered | inputs |
| 12x2 | confidential entry | min | 28 | sol | 12 | 12 | 60 | 12 | 3941 | 3968 | buffered | inputs |
| 12x2 | confidential entry | min | 32 | sol | 12 | 12 | 64 | 12 | 3977 | 4004 | buffered | inputs |
| 12x2 | confidential entry | full | 0 | sol | 10 | 10 | 35 | 12 | 3742 | 3725 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 1 | sol | 10 | 10 | 37 | 12 | 3751 | 3734 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 4 | sol | 10 | 10 | 40 | 12 | 3778 | 3761 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 8 | sol | 10 | 10 | 44 | 12 | 3814 | 3797 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 12 | sol | 10 | 10 | 48 | 12 | 3850 | 3833 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 16 | sol | 10 | 10 | 52 | 12 | 3886 | 3869 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 20 | sol | 10 | 10 | 56 | 12 | 3922 | 3905 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 24 | sol | 10 | 10 | 60 | 12 | 3958 | 3941 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 28 | sol | 10 | 10 | 64 | 12 | 3994 | 3977 | buffered | 1 accounts, 1 signatures |
| 12x2 | confidential entry | full | 32 | sol | 6 | 6 | 64 | 8 | 4030 | 4013 | buffered | 1 accounts |
| 12x2 | confidential entry | full+data+reply | 0 | sol | 10 | 10 | 35 | 12 | 3942 | 3921 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 1 | sol | 10 | 10 | 37 | 12 | 3951 | 3930 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 4 | sol | 10 | 10 | 40 | 12 | 3978 | 3957 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 8 | sol | 10 | 10 | 44 | 12 | 4014 | 3993 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 12 | sol | 10 | 10 | 48 | 12 | 4050 | 4029 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 16 | sol | 10 | 10 | 52 | 12 | 4086 | 4065 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 20 | sol | 10 | 10 | 56 | 12 | 4122 | 4101 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 24 | sol | 10 | 10 | 60 | 12 | 4158 | 4137 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 28 | sol | 10 | 10 | 64 | 12 | 4194 | 4173 | buffered | 1 accounts, 1 signatures |
| 12x2 | confidential entry | full+data+reply | 32 | sol | 6 | 6 | 64 | 8 | 4230 | 4209 | buffered | 1 accounts |
| 12x2 | confidential entry | min | 0 | spl | 12 | 12 | 31 | 12 | 3689 | 3716 | buffered | inputs |
| 12x2 | confidential entry | min | 1 | spl | 12 | 12 | 36 | 12 | 3699 | 3726 | buffered | inputs |
| 12x2 | confidential entry | min | 4 | spl | 12 | 12 | 43 | 12 | 3729 | 3756 | buffered | inputs |
| 12x2 | confidential entry | min | 8 | spl | 12 | 12 | 47 | 12 | 3769 | 3796 | buffered | inputs |
| 12x2 | confidential entry | min | 12 | spl | 12 | 12 | 51 | 12 | 3809 | 3836 | buffered | inputs |
| 12x2 | confidential entry | min | 16 | spl | 12 | 12 | 55 | 12 | 3849 | 3876 | buffered | inputs |
| 12x2 | confidential entry | min | 20 | spl | 12 | 12 | 59 | 12 | 3889 | 3916 | buffered | inputs |
| 12x2 | confidential entry | min | 24 | spl | 12 | 12 | 63 | 12 | 3929 | 3956 | buffered | inputs |
| 12x2 | confidential entry | min | 28 | spl | 9 | 9 | 64 | 9 | 3969 | 3996 | buffered | 1 accounts |
| 12x2 | confidential entry | min | 32 | spl | 5 | 5 | 64 | 5 | 4009 | 4036 | buffered | 1 accounts |
| 12x2 | confidential entry | full | 0 | spl | 10 | 10 | 35 | 12 | 3742 | 3725 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 1 | spl | 10 | 10 | 40 | 12 | 3784 | 3735 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 4 | spl | 10 | 10 | 47 | 12 | 3910 | 3765 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 8 | spl | 10 | 10 | 51 | 12 | 4078 | 3805 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 12 | spl | 10 | 10 | 55 | 12 | 4246 | 3845 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 16 | spl | 10 | 10 | 59 | 12 | 4414 | 3885 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 20 | spl | 10 | 10 | 63 | 12 | 4582 | 3925 | buffered | 1 signatures |
| 12x2 | confidential entry | full | 24 | spl | 7 | 7 | 64 | 9 | 4750 | 3965 | buffered | 1 accounts |
| 12x2 | confidential entry | full | 28 | spl | 3 | 3 | 64 | 5 | 4918 | 4005 | buffered | 1 accounts |
| 12x2 | confidential entry | full | 32 | spl | none | - | - | - | - | - | no | 2 accounts |
| 12x2 | confidential entry | full+data+reply | 0 | spl | 10 | 10 | 35 | 12 | 3942 | 3921 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 1 | spl | 10 | 10 | 40 | 12 | 3984 | 3931 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 4 | spl | 10 | 10 | 47 | 12 | 4110 | 3961 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 8 | spl | 10 | 10 | 51 | 12 | 4278 | 4001 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 12 | spl | 10 | 10 | 55 | 12 | 4446 | 4041 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 16 | spl | 10 | 10 | 59 | 12 | 4614 | 4081 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 20 | spl | 10 | 10 | 63 | 12 | 4782 | 4121 | buffered | 1 signatures |
| 12x2 | confidential entry | full+data+reply | 24 | spl | 7 | 7 | 64 | 9 | 4950 | 4161 | buffered | 1 accounts |
| 12x2 | confidential entry | full+data+reply | 28 | spl | 3 | 3 | 64 | 5 | 5118 | 4201 | buffered | 1 accounts |
| 12x2 | confidential entry | full+data+reply | 32 | spl | none | - | - | - | - | - | no | 2 accounts |
| 12x2 | anonymous entry | min | 0 | sol | 11 | 12 | 31 | 12 | 3889 | 3915 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 1 | sol | 11 | 12 | 33 | 12 | 3898 | 3924 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 4 | sol | 11 | 12 | 33 | 12 | 3925 | 3951 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 8 | sol | 11 | 12 | 33 | 12 | 3961 | 3987 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 12 | sol | 11 | 12 | 33 | 12 | 3997 | 4023 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 16 | sol | 11 | 12 | 33 | 12 | 4033 | 4059 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 20 | sol | 11 | 12 | 33 | 12 | 4069 | 4095 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 24 | sol | 11 | 12 | 33 | 12 | 4105 | 4131 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 28 | sol | 11 | 12 | 33 | 12 | 4141 | 4167 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 32 | sol | 11 | 12 | 33 | 12 | 4177 | 4203 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 0 | sol | 10 | 11 | 35 | 12 | 4014 | 4006 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 1 | sol | 10 | 11 | 37 | 12 | 4023 | 4015 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 4 | sol | 10 | 11 | 37 | 12 | 4050 | 4042 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 8 | sol | 10 | 11 | 37 | 12 | 4086 | 4078 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 12 | sol | 10 | 11 | 37 | 12 | 4122 | 4114 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 16 | sol | 10 | 11 | 37 | 12 | 4158 | 4150 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 20 | sol | 10 | 11 | 37 | 12 | 4194 | 4186 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 24 | sol | 10 | 11 | 37 | 12 | 4230 | 4222 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 28 | sol | 10 | 11 | 37 | 12 | 4266 | 4258 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 32 | sol | 10 | 11 | 37 | 12 | 4302 | 4294 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 0 | sol | 10 | 11 | 35 | 12 | 4313 | 4299 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 1 | sol | 10 | 11 | 37 | 12 | 4322 | 4308 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 4 | sol | 10 | 11 | 37 | 12 | 4349 | 4335 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 8 | sol | 10 | 11 | 37 | 12 | 4385 | 4371 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 12 | sol | 10 | 11 | 37 | 12 | 4421 | 4407 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 16 | sol | 10 | 11 | 37 | 12 | 4457 | 4443 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 20 | sol | 10 | 11 | 37 | 12 | 4493 | 4479 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 24 | sol | 10 | 11 | 37 | 12 | 4529 | 4515 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 28 | sol | 10 | 11 | 37 | 12 | 4565 | 4551 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 32 | sol | 10 | 11 | 37 | 12 | 4601 | 4587 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 0 | spl | 11 | 12 | 31 | 12 | 3889 | 3915 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 1 | spl | 11 | 12 | 36 | 12 | 3899 | 3925 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 4 | spl | 11 | 12 | 40 | 12 | 3929 | 3955 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 8 | spl | 11 | 12 | 40 | 12 | 3969 | 3995 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 12 | spl | 11 | 12 | 40 | 12 | 4009 | 4035 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 16 | spl | 11 | 12 | 40 | 12 | 4049 | 4075 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 20 | spl | 11 | 12 | 40 | 12 | 4089 | 4115 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 24 | spl | 11 | 12 | 40 | 12 | 4129 | 4155 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 28 | spl | 11 | 12 | 40 | 12 | 4169 | 4195 | buffered | 1 signatures |
| 12x2 | anonymous entry | min | 32 | spl | 11 | 12 | 40 | 12 | 4209 | 4235 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 0 | spl | 10 | 11 | 35 | 12 | 4014 | 4006 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 1 | spl | 10 | 11 | 40 | 12 | 4056 | 4016 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 4 | spl | 10 | 11 | 44 | 12 | 4182 | 4046 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 8 | spl | 10 | 11 | 44 | 12 | 4350 | 4086 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 12 | spl | 10 | 11 | 44 | 12 | 4518 | 4126 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 16 | spl | 10 | 11 | 44 | 12 | 4686 | 4166 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 20 | spl | 10 | 11 | 44 | 12 | 4854 | 4206 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 24 | spl | 10 | 11 | 44 | 12 | 5022 | 4246 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 28 | spl | 10 | 11 | 44 | 12 | 5190 | 4286 | buffered | 1 signatures |
| 12x2 | anonymous entry | full | 32 | spl | 10 | 11 | 44 | 12 | 5358 | 4326 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 0 | spl | 10 | 11 | 35 | 12 | 4313 | 4299 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 1 | spl | 10 | 11 | 40 | 12 | 4355 | 4309 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 4 | spl | 10 | 11 | 44 | 12 | 4481 | 4339 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 8 | spl | 10 | 11 | 44 | 12 | 4649 | 4379 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 12 | spl | 10 | 11 | 44 | 12 | 4817 | 4419 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 16 | spl | 10 | 11 | 44 | 12 | 4985 | 4459 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 20 | spl | 10 | 11 | 44 | 12 | 5153 | 4499 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 24 | spl | 10 | 11 | 44 | 12 | 5321 | 4539 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 28 | spl | 10 | 11 | 44 | 12 | 5489 | 4579 | buffered | 1 signatures |
| 12x2 | anonymous entry | full+data+reply | 32 | spl | 10 | 11 | 44 | 12 | 5657 | 4619 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 0 | sol | 12 | 12 | 35 | 12 | 4617 | 4648 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 1 | sol | 12 | 12 | 37 | 12 | 4626 | 4657 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 4 | sol | 12 | 12 | 40 | 12 | 4653 | 4684 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 8 | sol | 12 | 12 | 44 | 12 | 4689 | 4720 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 12 | sol | 12 | 12 | 48 | 12 | 4725 | 4756 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 16 | sol | 12 | 12 | 52 | 12 | 4761 | 4792 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 20 | sol | 12 | 12 | 56 | 12 | 4797 | 4828 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 24 | sol | 12 | 12 | 60 | 12 | 4833 | 4864 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 28 | sol | 12 | 12 | 64 | 12 | 4869 | 4900 | buffered | 1 accounts, 1 signatures |
| 16x2 | confidential entry | min | 32 | sol | 8 | 8 | 64 | 8 | 4905 | 4936 | buffered | 1 accounts |
| 16x2 | confidential entry | full | 0 | sol | 10 | 10 | 39 | 12 | 4670 | 4657 | buffered | 1 signatures |
| 16x2 | confidential entry | full | 1 | sol | 10 | 10 | 41 | 12 | 4679 | 4666 | buffered | 1 signatures |
| 16x2 | confidential entry | full | 4 | sol | 10 | 10 | 44 | 12 | 4706 | 4693 | buffered | 1 signatures |
| 16x2 | confidential entry | full | 8 | sol | 10 | 10 | 48 | 12 | 4742 | 4729 | buffered | 1 signatures |
| 16x2 | confidential entry | full | 12 | sol | 10 | 10 | 52 | 12 | 4778 | 4765 | buffered | 1 signatures |
| 16x2 | confidential entry | full | 16 | sol | 10 | 10 | 56 | 12 | 4814 | 4801 | buffered | 1 signatures |
| 16x2 | confidential entry | full | 20 | sol | 10 | 10 | 60 | 12 | 4850 | 4837 | buffered | 1 signatures |
| 16x2 | confidential entry | full | 24 | sol | 10 | 10 | 64 | 12 | 4886 | 4873 | buffered | 1 accounts, 1 signatures |
| 16x2 | confidential entry | full | 28 | sol | 6 | 6 | 64 | 8 | 4922 | 4909 | buffered | 1 accounts |
| 16x2 | confidential entry | full | 32 | sol | 2 | 2 | 64 | 4 | 4958 | 4945 | buffered | 1 accounts |
| 16x2 | confidential entry | full+data+reply | 0 | sol | 10 | 10 | 39 | 12 | 4870 | 4853 | buffered | 1 signatures |
| 16x2 | confidential entry | full+data+reply | 1 | sol | 10 | 10 | 41 | 12 | 4879 | 4862 | buffered | 1 signatures |
| 16x2 | confidential entry | full+data+reply | 4 | sol | 10 | 10 | 44 | 12 | 4906 | 4889 | buffered | 1 signatures |
| 16x2 | confidential entry | full+data+reply | 8 | sol | 10 | 10 | 48 | 12 | 4942 | 4925 | buffered | 1 signatures |
| 16x2 | confidential entry | full+data+reply | 12 | sol | 10 | 10 | 52 | 12 | 4978 | 4961 | buffered | 1 signatures |
| 16x2 | confidential entry | full+data+reply | 16 | sol | 10 | 10 | 56 | 12 | 5014 | 4997 | buffered | 1 signatures |
| 16x2 | confidential entry | full+data+reply | 20 | sol | 10 | 10 | 60 | 12 | 5050 | 5033 | buffered | 1 signatures |
| 16x2 | confidential entry | full+data+reply | 24 | sol | 10 | 10 | 64 | 12 | 5086 | 5069 | buffered | 1 accounts, 1 signatures |
| 16x2 | confidential entry | full+data+reply | 28 | sol | 6 | 6 | 64 | 8 | 5122 | 5105 | buffered | 1 accounts |
| 16x2 | confidential entry | full+data+reply | 32 | sol | 2 | 2 | 64 | 4 | 5158 | 5141 | buffered | 1 accounts |
| 16x2 | confidential entry | min | 0 | spl | 12 | 12 | 35 | 12 | 4617 | 4648 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 1 | spl | 12 | 12 | 40 | 12 | 4627 | 4658 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 4 | spl | 12 | 12 | 47 | 12 | 4657 | 4688 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 8 | spl | 12 | 12 | 51 | 12 | 4697 | 4728 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 12 | spl | 12 | 12 | 55 | 12 | 4737 | 4768 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 16 | spl | 12 | 12 | 59 | 12 | 4777 | 4808 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 20 | spl | 12 | 12 | 63 | 12 | 4817 | 4848 | buffered | 1 signatures |
| 16x2 | confidential entry | min | 24 | spl | 9 | 9 | 64 | 9 | 4857 | 4888 | buffered | 1 accounts |
| 16x2 | confidential entry | min | 28 | spl | 5 | 5 | 64 | 5 | 4897 | 4928 | buffered | 1 accounts |
| 16x2 | confidential entry | min | 32 | spl | 1 | 1 | 64 | 1 | 4937 | 4968 | buffered | 1 accounts |
| 16x2 | confidential entry | full | 0 | spl | 10 | 10 | 39 | 12 | 4670 | 4657 | buffered | 1 signatures |
| 16x2 | confidential entry | full | 1 | spl | 10 | 10 | 44 | 12 | 4712 | 4667 | buffered | 1 signatures |
| 16x2 | confidential entry | full | 4 | spl | 10 | 10 | 51 | 12 | 4838 | 4697 | buffered | 1 signatures |
| 16x2 | confidential entry | full | 8 | spl | 10 | 10 | 55 | 12 | 5006 | 4737 | buffered | 1 signatures |
| 16x2 | confidential entry | full | 12 | spl | 10 | 10 | 59 | 12 | 5174 | 4777 | buffered | 1 signatures |
| 16x2 | confidential entry | full | 16 | spl | 10 | 10 | 63 | 12 | 5342 | 4817 | buffered | 1 signatures |
| 16x2 | confidential entry | full | 20 | spl | 7 | 7 | 64 | 9 | 5510 | 4857 | buffered | 1 accounts |
| 16x2 | confidential entry | full | 24 | spl | 3 | 3 | 64 | 5 | 5678 | 4897 | buffered | 1 accounts |
| 16x2 | confidential entry | full | 28 | spl | none | - | - | - | - | - | no | 2 accounts |
| 16x2 | confidential entry | full+data+reply | 0 | spl | 10 | 10 | 39 | 12 | 4870 | 4853 | buffered | 1 signatures |
| 16x2 | confidential entry | full+data+reply | 1 | spl | 10 | 10 | 44 | 12 | 4912 | 4863 | buffered | 1 signatures |
| 16x2 | confidential entry | full+data+reply | 4 | spl | 10 | 10 | 51 | 12 | 5038 | 4893 | buffered | 1 signatures |
| 16x2 | confidential entry | full+data+reply | 8 | spl | 10 | 10 | 55 | 12 | 5206 | 4933 | buffered | 1 signatures |
| 16x2 | confidential entry | full+data+reply | 12 | spl | 10 | 10 | 59 | 12 | 5374 | 4973 | buffered | 1 signatures |
| 16x2 | confidential entry | full+data+reply | 16 | spl | 10 | 10 | 63 | 12 | 5542 | 5013 | buffered | 1 signatures |
| 16x2 | confidential entry | full+data+reply | 20 | spl | 7 | 7 | 64 | 9 | 5710 | 5053 | buffered | 1 accounts |
| 16x2 | confidential entry | full+data+reply | 24 | spl | 3 | 3 | 64 | 5 | 5878 | 5093 | buffered | 1 accounts |
| 16x2 | confidential entry | full+data+reply | 28 | spl | none | - | - | - | - | - | no | 2 accounts |
| 16x2 | anonymous entry | min | 0 | sol | 11 | 12 | 35 | 12 | 4817 | 4847 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 1 | sol | 11 | 12 | 37 | 12 | 4826 | 4856 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 4 | sol | 11 | 12 | 37 | 12 | 4853 | 4883 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 8 | sol | 11 | 12 | 37 | 12 | 4889 | 4919 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 12 | sol | 11 | 12 | 37 | 12 | 4925 | 4955 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 16 | sol | 11 | 12 | 37 | 12 | 4961 | 4991 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 20 | sol | 11 | 12 | 37 | 12 | 4997 | 5027 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 24 | sol | 11 | 12 | 37 | 12 | 5033 | 5063 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 28 | sol | 11 | 12 | 37 | 12 | 5069 | 5099 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 32 | sol | 11 | 12 | 37 | 12 | 5105 | 5135 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 0 | sol | 10 | 11 | 39 | 12 | 4942 | 4938 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 1 | sol | 10 | 11 | 41 | 12 | 4951 | 4947 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 4 | sol | 10 | 11 | 41 | 12 | 4978 | 4974 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 8 | sol | 10 | 11 | 41 | 12 | 5014 | 5010 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 12 | sol | 10 | 11 | 41 | 12 | 5050 | 5046 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 16 | sol | 10 | 11 | 41 | 12 | 5086 | 5082 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 20 | sol | 10 | 11 | 41 | 12 | 5122 | 5118 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 24 | sol | 10 | 11 | 41 | 12 | 5158 | 5154 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 28 | sol | 10 | 11 | 41 | 12 | 5194 | 5190 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 32 | sol | 10 | 11 | 41 | 12 | 5230 | 5226 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 0 | sol | 10 | 11 | 39 | 12 | 5241 | 5231 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 1 | sol | 10 | 11 | 41 | 12 | 5250 | 5240 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 4 | sol | 10 | 11 | 41 | 12 | 5277 | 5267 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 8 | sol | 10 | 11 | 41 | 12 | 5313 | 5303 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 12 | sol | 10 | 11 | 41 | 12 | 5349 | 5339 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 16 | sol | 10 | 11 | 41 | 12 | 5385 | 5375 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 20 | sol | 10 | 11 | 41 | 12 | 5421 | 5411 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 24 | sol | 10 | 11 | 41 | 12 | 5457 | 5447 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 28 | sol | 10 | 11 | 41 | 12 | 5493 | 5483 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 32 | sol | 10 | 11 | 41 | 12 | 5529 | 5519 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 0 | spl | 11 | 12 | 35 | 12 | 4817 | 4847 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 1 | spl | 11 | 12 | 40 | 12 | 4827 | 4857 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 4 | spl | 11 | 12 | 44 | 12 | 4857 | 4887 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 8 | spl | 11 | 12 | 44 | 12 | 4897 | 4927 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 12 | spl | 11 | 12 | 44 | 12 | 4937 | 4967 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 16 | spl | 11 | 12 | 44 | 12 | 4977 | 5007 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 20 | spl | 11 | 12 | 44 | 12 | 5017 | 5047 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 24 | spl | 11 | 12 | 44 | 12 | 5057 | 5087 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 28 | spl | 11 | 12 | 44 | 12 | 5097 | 5127 | buffered | 1 signatures |
| 16x2 | anonymous entry | min | 32 | spl | 11 | 12 | 44 | 12 | 5137 | 5167 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 0 | spl | 10 | 11 | 39 | 12 | 4942 | 4938 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 1 | spl | 10 | 11 | 44 | 12 | 4984 | 4948 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 4 | spl | 10 | 11 | 48 | 12 | 5110 | 4978 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 8 | spl | 10 | 11 | 48 | 12 | 5278 | 5018 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 12 | spl | 10 | 11 | 48 | 12 | 5446 | 5058 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 16 | spl | 10 | 11 | 48 | 12 | 5614 | 5098 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 20 | spl | 10 | 11 | 48 | 12 | 5782 | 5138 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 24 | spl | 10 | 11 | 48 | 12 | 5950 | 5178 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 28 | spl | 10 | 11 | 48 | 12 | 6118 | 5218 | buffered | 1 signatures |
| 16x2 | anonymous entry | full | 32 | spl | 10 | 11 | 48 | 12 | 6286 | 5258 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 0 | spl | 10 | 11 | 39 | 12 | 5241 | 5231 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 1 | spl | 10 | 11 | 44 | 12 | 5283 | 5241 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 4 | spl | 10 | 11 | 48 | 12 | 5409 | 5271 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 8 | spl | 10 | 11 | 48 | 12 | 5577 | 5311 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 12 | spl | 10 | 11 | 48 | 12 | 5745 | 5351 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 16 | spl | 10 | 11 | 48 | 12 | 5913 | 5391 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 20 | spl | 10 | 11 | 48 | 12 | 6081 | 5431 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 24 | spl | 10 | 11 | 48 | 12 | 6249 | 5471 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 28 | spl | 10 | 11 | 48 | 12 | 6417 | 5511 | buffered | 1 signatures |
| 16x2 | anonymous entry | full+data+reply | 32 | spl | 10 | 11 | 48 | 12 | 6585 | 5551 | buffered | 1 signatures |
| 24x2 | confidential entry | min | 0 | sol | 12 | 12 | 43 | 12 | 6473 | 6512 | buffered | 1 signatures |
| 24x2 | confidential entry | min | 1 | sol | 12 | 12 | 45 | 12 | 6482 | 6521 | buffered | 1 signatures |
| 24x2 | confidential entry | min | 4 | sol | 12 | 12 | 48 | 12 | 6509 | 6548 | buffered | 1 signatures |
| 24x2 | confidential entry | min | 8 | sol | 12 | 12 | 52 | 12 | 6545 | 6584 | buffered | 1 signatures |
| 24x2 | confidential entry | min | 12 | sol | 12 | 12 | 56 | 12 | 6581 | 6620 | buffered | 1 signatures |
| 24x2 | confidential entry | min | 16 | sol | 12 | 12 | 60 | 12 | 6617 | 6656 | buffered | 1 signatures |
| 24x2 | confidential entry | min | 20 | sol | 12 | 12 | 64 | 12 | 6653 | 6692 | buffered | 1 accounts, 1 signatures |
| 24x2 | confidential entry | min | 24 | sol | 8 | 8 | 64 | 8 | 6689 | 6728 | buffered | 1 accounts |
| 24x2 | confidential entry | min | 28 | sol | 4 | 4 | 64 | 4 | 6725 | 6764 | buffered | 1 accounts |
| 24x2 | confidential entry | min | 32 | sol | none | - | - | - | - | - | no | 1 accounts |
| 24x2 | confidential entry | full | 0 | sol | 10 | 10 | 47 | 12 | 6526 | 6521 | buffered | 1 signatures |
| 24x2 | confidential entry | full | 1 | sol | 10 | 10 | 49 | 12 | 6535 | 6530 | buffered | 1 signatures |
| 24x2 | confidential entry | full | 4 | sol | 10 | 10 | 52 | 12 | 6562 | 6557 | buffered | 1 signatures |
| 24x2 | confidential entry | full | 8 | sol | 10 | 10 | 56 | 12 | 6598 | 6593 | buffered | 1 signatures |
| 24x2 | confidential entry | full | 12 | sol | 10 | 10 | 60 | 12 | 6634 | 6629 | buffered | 1 signatures |
| 24x2 | confidential entry | full | 16 | sol | 10 | 10 | 64 | 12 | 6670 | 6665 | buffered | 1 accounts, 1 signatures |
| 24x2 | confidential entry | full | 20 | sol | 6 | 6 | 64 | 8 | 6706 | 6701 | buffered | 1 accounts |
| 24x2 | confidential entry | full | 24 | sol | 2 | 2 | 64 | 4 | 6742 | 6737 | buffered | 1 accounts |
| 24x2 | confidential entry | full | 28 | sol | none | - | - | - | - | - | no | 3 accounts |
| 24x2 | confidential entry | full+data+reply | 0 | sol | 10 | 10 | 47 | 12 | 6726 | 6717 | buffered | 1 signatures |
| 24x2 | confidential entry | full+data+reply | 1 | sol | 10 | 10 | 49 | 12 | 6735 | 6726 | buffered | 1 signatures |
| 24x2 | confidential entry | full+data+reply | 4 | sol | 10 | 10 | 52 | 12 | 6762 | 6753 | buffered | 1 signatures |
| 24x2 | confidential entry | full+data+reply | 8 | sol | 10 | 10 | 56 | 12 | 6798 | 6789 | buffered | 1 signatures |
| 24x2 | confidential entry | full+data+reply | 12 | sol | 10 | 10 | 60 | 12 | 6834 | 6825 | buffered | 1 signatures |
| 24x2 | confidential entry | full+data+reply | 16 | sol | 10 | 10 | 64 | 12 | 6870 | 6861 | buffered | 1 accounts, 1 signatures |
| 24x2 | confidential entry | full+data+reply | 20 | sol | 6 | 6 | 64 | 8 | 6906 | 6897 | buffered | 1 accounts |
| 24x2 | confidential entry | full+data+reply | 24 | sol | 2 | 2 | 64 | 4 | 6942 | 6933 | buffered | 1 accounts |
| 24x2 | confidential entry | full+data+reply | 28 | sol | none | - | - | - | - | - | no | 3 accounts |
| 24x2 | confidential entry | min | 0 | spl | 12 | 12 | 43 | 12 | 6473 | 6512 | buffered | 1 signatures |
| 24x2 | confidential entry | min | 1 | spl | 12 | 12 | 48 | 12 | 6483 | 6522 | buffered | 1 signatures |
| 24x2 | confidential entry | min | 4 | spl | 12 | 12 | 55 | 12 | 6513 | 6552 | buffered | 1 signatures |
| 24x2 | confidential entry | min | 8 | spl | 12 | 12 | 59 | 12 | 6553 | 6592 | buffered | 1 signatures |
| 24x2 | confidential entry | min | 12 | spl | 12 | 12 | 63 | 12 | 6593 | 6632 | buffered | 1 signatures |
| 24x2 | confidential entry | min | 16 | spl | 9 | 9 | 64 | 9 | 6633 | 6672 | buffered | 1 accounts |
| 24x2 | confidential entry | min | 20 | spl | 5 | 5 | 64 | 5 | 6673 | 6712 | buffered | 1 accounts |
| 24x2 | confidential entry | min | 24 | spl | 1 | 1 | 64 | 1 | 6713 | 6752 | buffered | 1 accounts |
| 24x2 | confidential entry | min | 28 | spl | none | - | - | - | - | - | no | 4 accounts |
| 24x2 | confidential entry | full | 0 | spl | 10 | 10 | 47 | 12 | 6526 | 6521 | buffered | 1 signatures |
| 24x2 | confidential entry | full | 1 | spl | 10 | 10 | 52 | 12 | 6568 | 6531 | buffered | 1 signatures |
| 24x2 | confidential entry | full | 4 | spl | 10 | 10 | 59 | 12 | 6694 | 6561 | buffered | 1 signatures |
| 24x2 | confidential entry | full | 8 | spl | 10 | 10 | 63 | 12 | 6862 | 6601 | buffered | 1 signatures |
| 24x2 | confidential entry | full | 12 | spl | 7 | 7 | 64 | 9 | 7030 | 6641 | buffered | 1 accounts |
| 24x2 | confidential entry | full | 16 | spl | 3 | 3 | 64 | 5 | 7198 | 6681 | buffered | 1 accounts |
| 24x2 | confidential entry | full | 20 | spl | none | - | - | - | - | - | no | 2 accounts |
| 24x2 | confidential entry | full+data+reply | 0 | spl | 10 | 10 | 47 | 12 | 6726 | 6717 | buffered | 1 signatures |
| 24x2 | confidential entry | full+data+reply | 1 | spl | 10 | 10 | 52 | 12 | 6768 | 6727 | buffered | 1 signatures |
| 24x2 | confidential entry | full+data+reply | 4 | spl | 10 | 10 | 59 | 12 | 6894 | 6757 | buffered | 1 signatures |
| 24x2 | confidential entry | full+data+reply | 8 | spl | 10 | 10 | 63 | 12 | 7062 | 6797 | buffered | 1 signatures |
| 24x2 | confidential entry | full+data+reply | 12 | spl | 7 | 7 | 64 | 9 | 7230 | 6837 | buffered | 1 accounts |
| 24x2 | confidential entry | full+data+reply | 16 | spl | 3 | 3 | 64 | 5 | 7398 | 6877 | buffered | 1 accounts |
| 24x2 | confidential entry | full+data+reply | 20 | spl | none | - | - | - | - | - | no | 2 accounts |
| 24x2 | anonymous entry | min | 0 | sol | 11 | 12 | 43 | 12 | 6673 | 6711 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 1 | sol | 11 | 12 | 45 | 12 | 6682 | 6720 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 4 | sol | 11 | 12 | 45 | 12 | 6709 | 6747 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 8 | sol | 11 | 12 | 45 | 12 | 6745 | 6783 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 12 | sol | 11 | 12 | 45 | 12 | 6781 | 6819 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 16 | sol | 11 | 12 | 45 | 12 | 6817 | 6855 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 20 | sol | 11 | 12 | 45 | 12 | 6853 | 6891 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 24 | sol | 11 | 12 | 45 | 12 | 6889 | 6927 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 28 | sol | 11 | 12 | 45 | 12 | 6925 | 6963 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 32 | sol | 11 | 12 | 45 | 12 | 6961 | 6999 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 0 | sol | 10 | 11 | 47 | 12 | 6798 | 6802 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 1 | sol | 10 | 11 | 49 | 12 | 6807 | 6811 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 4 | sol | 10 | 11 | 49 | 12 | 6834 | 6838 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 8 | sol | 10 | 11 | 49 | 12 | 6870 | 6874 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 12 | sol | 10 | 11 | 49 | 12 | 6906 | 6910 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 16 | sol | 10 | 11 | 49 | 12 | 6942 | 6946 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 20 | sol | 10 | 11 | 49 | 12 | 6978 | 6982 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 24 | sol | 10 | 11 | 49 | 12 | 7014 | 7018 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 28 | sol | 10 | 11 | 49 | 12 | 7050 | 7054 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 32 | sol | 10 | 11 | 49 | 12 | 7086 | 7090 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 0 | sol | 10 | 11 | 47 | 12 | 7097 | 7095 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 1 | sol | 10 | 11 | 49 | 12 | 7106 | 7104 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 4 | sol | 10 | 11 | 49 | 12 | 7133 | 7131 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 8 | sol | 10 | 11 | 49 | 12 | 7169 | 7167 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 12 | sol | 10 | 11 | 49 | 12 | 7205 | 7203 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 16 | sol | 10 | 11 | 49 | 12 | 7241 | 7239 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 20 | sol | 10 | 11 | 49 | 12 | 7277 | 7275 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 24 | sol | 10 | 11 | 49 | 12 | 7313 | 7311 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 28 | sol | 10 | 11 | 49 | 12 | 7349 | 7347 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 32 | sol | 10 | 11 | 49 | 12 | 7385 | 7383 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 0 | spl | 11 | 12 | 43 | 12 | 6673 | 6711 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 1 | spl | 11 | 12 | 48 | 12 | 6683 | 6721 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 4 | spl | 11 | 12 | 52 | 12 | 6713 | 6751 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 8 | spl | 11 | 12 | 52 | 12 | 6753 | 6791 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 12 | spl | 11 | 12 | 52 | 12 | 6793 | 6831 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 16 | spl | 11 | 12 | 52 | 12 | 6833 | 6871 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 20 | spl | 11 | 12 | 52 | 12 | 6873 | 6911 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 24 | spl | 11 | 12 | 52 | 12 | 6913 | 6951 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 28 | spl | 11 | 12 | 52 | 12 | 6953 | 6991 | buffered | 1 signatures |
| 24x2 | anonymous entry | min | 32 | spl | 11 | 12 | 52 | 12 | 6993 | 7031 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 0 | spl | 10 | 11 | 47 | 12 | 6798 | 6802 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 1 | spl | 10 | 11 | 52 | 12 | 6840 | 6812 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 4 | spl | 10 | 11 | 56 | 12 | 6966 | 6842 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 8 | spl | 10 | 11 | 56 | 12 | 7134 | 6882 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 12 | spl | 10 | 11 | 56 | 12 | 7302 | 6922 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 16 | spl | 10 | 11 | 56 | 12 | 7470 | 6962 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 20 | spl | 10 | 11 | 56 | 12 | 7638 | 7002 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 24 | spl | 10 | 11 | 56 | 12 | 7806 | 7042 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 28 | spl | 10 | 11 | 56 | 12 | 7974 | 7082 | buffered | 1 signatures |
| 24x2 | anonymous entry | full | 32 | spl | 10 | 11 | 56 | 12 | 8142 | 7122 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 0 | spl | 10 | 11 | 47 | 12 | 7097 | 7095 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 1 | spl | 10 | 11 | 52 | 12 | 7139 | 7105 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 4 | spl | 10 | 11 | 56 | 12 | 7265 | 7135 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 8 | spl | 10 | 11 | 56 | 12 | 7433 | 7175 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 12 | spl | 10 | 11 | 56 | 12 | 7601 | 7215 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 16 | spl | 10 | 11 | 56 | 12 | 7769 | 7255 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 20 | spl | 10 | 11 | 56 | 12 | 7937 | 7295 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 24 | spl | 10 | 11 | 56 | 12 | 8105 | 7335 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 28 | spl | 10 | 11 | 56 | 12 | 8273 | 7375 | buffered | 1 signatures |
| 24x2 | anonymous entry | full+data+reply | 32 | spl | 10 | 11 | 56 | 12 | 8441 | 7415 | buffered | 1 signatures |

Buffered maxima. Load max is full with data tails, every extension but the cache, two SPP input trees and four disjoint credential state trees, replies on anonymous frames. Each row widens one axis from that load to the largest value any path settles. reply: the reply length. messages: empty application messages. message bytes: one application message. writes: WriteFrame transactions the SDK sends before a buffered settle. over: what refuses one more step. Heap is not measured here.
| shape | rail | axis | widest | frame | SPP CPI | buffered bytes | buffered accounts | signatures | writes | fits | over |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1x2 | confidential signer | messages | 254 | 9969 | 9890 | 1116 | 25 | 3 | 3 | buffered | confidential signer Shape { n_inputs: 1, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 1x2 | confidential signer | message bytes | 8839 | 10206 | 10127 | 1116 | 25 | 3 | 3 | buffered | buffer create 1 B |
| 1x2 | confidential in-proof | messages | 254 | 10065 | 9987 | 1019 | 24 | 2 | 3 | buffered | confidential in-proof Shape { n_inputs: 1, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 1x2 | confidential in-proof | message bytes | 8743 | 10206 | 10128 | 1019 | 24 | 2 | 3 | buffered | buffer create 1 B |
| 1x2 | anonymous hidden | reply | 8632 | 10206 | 10167 | 923 | 21 | 2 | 3 | buffered | buffer create 1 B |
| 1x2 | anonymous hidden | messages | 251 | 10206 | 10166 | 923 | 21 | 2 | 3 | buffered | buffer create 34 B |
| 1x2 | anonymous hidden | message bytes | 8500 | 10206 | 10166 | 923 | 21 | 2 | 3 | buffered | buffer create 1 B |
| 1x2 | anonymous public owners | reply | 8696 | 10206 | 10134 | 1116 | 25 | 3 | 3 | buffered | buffer create 1 B |
| 1x2 | anonymous public owners | messages | 252 | 10176 | 10103 | 1116 | 25 | 3 | 3 | buffered | buffer create 4 B |
| 1x2 | anonymous public owners | message bytes | 8564 | 10206 | 10133 | 1116 | 25 | 3 | 3 | buffered | buffer create 1 B |
| 1x2 | confidential entry | messages | 254 | 10177 | 10098 | 1116 | 25 | 3 | 3 | buffered | confidential entry Shape { n_inputs: 1, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 1x2 | confidential entry | message bytes | 8631 | 10206 | 10127 | 1116 | 25 | 3 | 3 | buffered | buffer create 1 B |
| 1x2 | anonymous entry | reply | 8392 | 10206 | 10135 | 923 | 21 | 2 | 3 | buffered | buffer create 1 B |
| 1x2 | anonymous entry | messages | 243 | 10174 | 10102 | 923 | 21 | 2 | 3 | buffered | buffer create 2 B |
| 1x2 | anonymous entry | message bytes | 8260 | 10206 | 10134 | 923 | 21 | 2 | 3 | buffered | buffer create 1 B |
| 1x4 | confidential signer | messages | 242 | 10193 | 10182 | 1116 | 25 | 3 | 3 | buffered | buffer create 21 B |
| 1x4 | confidential signer | message bytes | 8207 | 10206 | 10195 | 1116 | 25 | 3 | 3 | buffered | buffer create 1 B |
| 1x4 | confidential in-proof | messages | 239 | 10187 | 10177 | 1019 | 24 | 2 | 3 | buffered | buffer create 15 B |
| 1x4 | confidential in-proof | message bytes | 8111 | 10206 | 10196 | 1019 | 24 | 2 | 3 | buffered | buffer create 1 B |
| 1x4 | anonymous hidden | reply | 2645 | 10205 | 10234 | 923 | 21 | 2 | 3 | buffered | buffer create 2 B |
| 1x4 | anonymous hidden | messages | 224 | 10178 | 10206 | 923 | 21 | 2 | 3 | buffered | buffer create 6 B |
| 1x4 | anonymous hidden | message bytes | 7610 | 10206 | 10234 | 923 | 21 | 2 | 3 | buffered | buffer create 1 B |
| 1x4 | anonymous public owners | reply | 2666 | 10204 | 10200 | 1116 | 25 | 3 | 3 | buffered | buffer create 1 B |
| 1x4 | anonymous public owners | messages | 226 | 10182 | 10177 | 1116 | 25 | 3 | 3 | buffered | buffer create 10 B |
| 1x4 | anonymous public owners | message bytes | 7674 | 10206 | 10201 | 1116 | 25 | 3 | 3 | buffered | buffer create 1 B |
| 1x4 | confidential entry | messages | 236 | 10197 | 10186 | 1116 | 25 | 3 | 3 | buffered | buffer create 25 B |
| 1x4 | confidential entry | message bytes | 7999 | 10206 | 10195 | 1116 | 25 | 3 | 3 | buffered | buffer create 1 B |
| 1x4 | anonymous entry | reply | 2565 | 10205 | 10202 | 923 | 21 | 2 | 3 | buffered | buffer create 2 B |
| 1x4 | anonymous entry | messages | 217 | 10180 | 10176 | 923 | 21 | 2 | 3 | buffered | buffer create 8 B |
| 1x4 | anonymous entry | message bytes | 7370 | 10206 | 10202 | 923 | 21 | 2 | 3 | buffered | buffer create 1 B |
| 1x8 | confidential signer | messages | 202 | 10097 | 10222 | 1116 | 25 | 3 | 3 | buffered | SPP CPI 16 B |
| 1x8 | confidential signer | message bytes | 6852 | 10115 | 10240 | 1116 | 25 | 3 | 3 | buffered | SPP CPI 1 B |
| 1x8 | confidential in-proof | messages | 199 | 10091 | 10217 | 1019 | 24 | 2 | 3 | buffered | SPP CPI 11 B |
| 1x8 | confidential in-proof | message bytes | 6755 | 10114 | 10240 | 1019 | 24 | 2 | 3 | buffered | SPP CPI 1 B |
| 1x8 | anonymous hidden | reply | 916 | 10074 | 10239 | 923 | 21 | 2 | 3 | buffered | SPP CPI 6 B |
| 1x8 | anonymous hidden | messages | 168 | 10054 | 10218 | 923 | 21 | 2 | 3 | buffered | SPP CPI 12 B |
| 1x8 | anonymous hidden | message bytes | 5700 | 10076 | 10240 | 923 | 21 | 2 | 3 | buffered | SPP CPI 1 B |
| 1x8 | anonymous public owners | reply | 930 | 10108 | 10240 | 1116 | 25 | 3 | 3 | buffered | SPP CPI 7 B |
| 1x8 | anonymous public owners | messages | 171 | 10092 | 10223 | 1116 | 25 | 3 | 3 | buffered | SPP CPI 17 B |
| 1x8 | anonymous public owners | message bytes | 5797 | 10109 | 10240 | 1116 | 25 | 3 | 3 | buffered | SPP CPI 1 B |
| 1x8 | confidential entry | messages | 196 | 10101 | 10226 | 1116 | 25 | 3 | 3 | buffered | SPP CPI 20 B |
| 1x8 | confidential entry | message bytes | 6644 | 10115 | 10240 | 1116 | 25 | 3 | 3 | buffered | SPP CPI 1 B |
| 1x8 | anonymous entry | reply | 886 | 10104 | 10237 | 923 | 21 | 2 | 3 | buffered | SPP CPI 4 B |
| 1x8 | anonymous entry | messages | 162 | 10090 | 10222 | 923 | 21 | 2 | 3 | buffered | SPP CPI 16 B |
| 1x8 | anonymous entry | message bytes | 5492 | 10108 | 10240 | 923 | 21 | 2 | 3 | buffered | SPP CPI 1 B |
| 2x2 | confidential signer | messages | 254 | 10001 | 9923 | 1149 | 26 | 3 | 3 | buffered | confidential signer Shape { n_inputs: 2, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 2x2 | confidential signer | message bytes | 8807 | 10206 | 10128 | 1149 | 26 | 3 | 3 | buffered | buffer create 1 B |
| 2x2 | confidential in-proof | messages | 254 | 10097 | 10020 | 1052 | 25 | 2 | 3 | buffered | confidential in-proof Shape { n_inputs: 2, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 2x2 | confidential in-proof | message bytes | 8711 | 10206 | 10129 | 1052 | 25 | 2 | 3 | buffered | buffer create 1 B |
| 2x2 | anonymous hidden | reply | 8600 | 10206 | 10168 | 956 | 22 | 2 | 3 | buffered | buffer create 1 B |
| 2x2 | anonymous hidden | messages | 250 | 10204 | 10165 | 956 | 22 | 2 | 3 | buffered | buffer create 32 B |
| 2x2 | anonymous hidden | message bytes | 8468 | 10206 | 10167 | 956 | 22 | 2 | 3 | buffered | buffer create 1 B |
| 2x2 | anonymous public owners | reply | 8664 | 10206 | 10135 | 1149 | 26 | 3 | 3 | buffered | buffer create 1 B |
| 2x2 | anonymous public owners | messages | 251 | 10174 | 10102 | 1149 | 26 | 3 | 3 | buffered | buffer create 2 B |
| 2x2 | anonymous public owners | message bytes | 8532 | 10206 | 10134 | 1149 | 26 | 3 | 3 | buffered | buffer create 1 B |
| 2x2 | confidential entry | messages | 248 | 10205 | 10127 | 1149 | 26 | 3 | 3 | buffered | buffer create 33 B |
| 2x2 | confidential entry | message bytes | 8399 | 10206 | 10128 | 1149 | 26 | 3 | 3 | buffered | buffer create 1 B |
| 2x2 | anonymous entry | reply | 8160 | 10206 | 10136 | 956 | 22 | 2 | 3 | buffered | buffer create 1 B |
| 2x2 | anonymous entry | messages | 237 | 10202 | 10131 | 956 | 22 | 2 | 3 | buffered | buffer create 30 B |
| 2x2 | anonymous entry | message bytes | 8028 | 10206 | 10135 | 956 | 22 | 2 | 3 | buffered | buffer create 1 B |
| 2x2 | delegate | messages | 254 | 9945 | 9923 | 953 | 22 | 2 | 3 | buffered | delegate Shape { n_inputs: 2, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 2x2 | delegate | message bytes | 8863 | 10206 | 10184 | 953 | 22 | 2 | 3 | buffered | buffer create 1 B |
| 2x2 | anonymous delegate | reply | 8720 | 10206 | 10191 | 953 | 22 | 2 | 3 | buffered | buffer create 1 B |
| 2x2 | anonymous delegate | messages | 253 | 10186 | 10170 | 953 | 22 | 2 | 3 | buffered | anonymous delegate Shape { n_inputs: 2, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 2x2 | anonymous delegate | message bytes | 8588 | 10206 | 10190 | 953 | 22 | 2 | 3 | buffered | buffer create 1 B |
| 2x4 | confidential signer | messages | 241 | 10191 | 10181 | 1149 | 26 | 3 | 3 | buffered | buffer create 19 B |
| 2x4 | confidential signer | message bytes | 8175 | 10206 | 10196 | 1149 | 26 | 3 | 3 | buffered | buffer create 1 B |
| 2x4 | confidential in-proof | messages | 238 | 10185 | 10176 | 1052 | 25 | 2 | 3 | buffered | buffer create 13 B |
| 2x4 | confidential in-proof | message bytes | 8079 | 10206 | 10197 | 1052 | 25 | 2 | 3 | buffered | buffer create 1 B |
| 2x4 | anonymous hidden | reply | 2634 | 10204 | 10234 | 956 | 22 | 2 | 3 | buffered | buffer create 1 B |
| 2x4 | anonymous hidden | messages | 223 | 10176 | 10205 | 956 | 22 | 2 | 3 | buffered | buffer create 4 B |
| 2x4 | anonymous hidden | message bytes | 7578 | 10206 | 10235 | 956 | 22 | 2 | 3 | buffered | buffer create 1 B |
| 2x4 | anonymous public owners | reply | 2656 | 10206 | 10203 | 1149 | 26 | 3 | 3 | buffered | buffer create 3 B |
| 2x4 | anonymous public owners | messages | 225 | 10180 | 10176 | 1149 | 26 | 3 | 3 | buffered | buffer create 8 B |
| 2x4 | anonymous public owners | message bytes | 7642 | 10206 | 10202 | 1149 | 26 | 3 | 3 | buffered | buffer create 1 B |
| 2x4 | confidential entry | messages | 229 | 10191 | 10181 | 1149 | 26 | 3 | 3 | buffered | buffer create 19 B |
| 2x4 | confidential entry | message bytes | 7767 | 10206 | 10196 | 1149 | 26 | 3 | 3 | buffered | buffer create 1 B |
| 2x4 | anonymous entry | reply | 2488 | 10206 | 10204 | 956 | 22 | 2 | 3 | buffered | buffer create 3 B |
| 2x4 | anonymous entry | messages | 210 | 10174 | 10171 | 956 | 22 | 2 | 3 | buffered | buffer create 2 B |
| 2x4 | anonymous entry | message bytes | 7138 | 10206 | 10203 | 956 | 22 | 2 | 3 | buffered | buffer create 1 B |
| 1x16 | confidential signer | messages | 120 | 9839 | 10234 | 1116 | 25 | 3 | 3 | buffered | SPP CPI 28 B |
| 1x16 | confidential signer | message bytes | 4052 | 9845 | 10240 | 1116 | 25 | 3 | 3 | buffered | SPP CPI 1 B |
| 1x16 | confidential in-proof | messages | 117 | 9833 | 10229 | 1019 | 24 | 2 | 3 | buffered | SPP CPI 23 B |
| 1x16 | confidential in-proof | message bytes | 3955 | 9844 | 10240 | 1019 | 24 | 2 | 3 | buffered | SPP CPI 1 B |
| 1x16 | anonymous hidden | reply | 223 | 9793 | 10228 | 923 | 21 | 2 | 3 | buffered | SPP CPI 3 B |
| 1x16 | anonymous hidden | messages | 55 | 9774 | 10208 | 923 | 21 | 2 | 3 | buffered | SPP CPI 2 B |
| 1x16 | anonymous hidden | message bytes | 1868 | 9806 | 10240 | 923 | 21 | 2 | 3 | buffered | SPP CPI 1 B |
| 1x16 | anonymous public owners | reply | 230 | 9834 | 10236 | 1116 | 25 | 3 | 3 | buffered | SPP CPI 11 B |
| 1x16 | anonymous public owners | messages | 58 | 9812 | 10213 | 1116 | 25 | 3 | 3 | buffered | SPP CPI 7 B |
| 1x16 | anonymous public owners | message bytes | 1965 | 9839 | 10240 | 1116 | 25 | 3 | 3 | buffered | SPP CPI 1 B |
| 2x8 | confidential signer | messages | 201 | 10095 | 10221 | 1149 | 26 | 3 | 3 | buffered | SPP CPI 15 B |
| 2x8 | confidential signer | message bytes | 6819 | 10114 | 10240 | 1149 | 26 | 3 | 3 | buffered | SPP CPI 1 B |
| 2x8 | confidential in-proof | messages | 198 | 10089 | 10216 | 1052 | 25 | 2 | 3 | buffered | SPP CPI 10 B |
| 2x8 | confidential in-proof | message bytes | 6722 | 10113 | 10240 | 1052 | 25 | 2 | 3 | buffered | SPP CPI 1 B |
| 2x8 | anonymous hidden | reply | 911 | 10071 | 10237 | 956 | 22 | 2 | 3 | buffered | SPP CPI 4 B |
| 2x8 | anonymous hidden | messages | 167 | 10052 | 10217 | 956 | 22 | 2 | 3 | buffered | SPP CPI 11 B |
| 2x8 | anonymous hidden | message bytes | 5667 | 10075 | 10240 | 956 | 22 | 2 | 3 | buffered | SPP CPI 1 B |
| 2x8 | anonymous public owners | reply | 925 | 10105 | 10238 | 1149 | 26 | 3 | 3 | buffered | SPP CPI 5 B |
| 2x8 | anonymous public owners | messages | 170 | 10090 | 10222 | 1149 | 26 | 3 | 3 | buffered | SPP CPI 16 B |
| 2x8 | anonymous public owners | message bytes | 5764 | 10108 | 10240 | 1149 | 26 | 3 | 3 | buffered | SPP CPI 1 B |
| 2x8 | confidential entry | messages | 189 | 10095 | 10221 | 1149 | 26 | 3 | 3 | buffered | SPP CPI 15 B |
| 2x8 | confidential entry | message bytes | 6411 | 10114 | 10240 | 1149 | 26 | 3 | 3 | buffered | SPP CPI 1 B |
| 2x8 | anonymous entry | reply | 853 | 10105 | 10239 | 956 | 22 | 2 | 3 | buffered | SPP CPI 6 B |
| 2x8 | anonymous entry | messages | 155 | 10084 | 10217 | 956 | 22 | 2 | 3 | buffered | SPP CPI 11 B |
| 2x8 | anonymous entry | message bytes | 5259 | 10107 | 10240 | 956 | 22 | 2 | 3 | buffered | SPP CPI 1 B |
| 3x2 | confidential signer | messages | 254 | 10033 | 9956 | 1182 | 27 | 3 | 3 | buffered | confidential signer Shape { n_inputs: 3, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 3x2 | confidential signer | message bytes | 8775 | 10206 | 10129 | 1182 | 27 | 3 | 3 | buffered | buffer create 1 B |
| 3x2 | confidential in-proof | messages | 254 | 10129 | 10053 | 1085 | 26 | 2 | 3 | buffered | confidential in-proof Shape { n_inputs: 3, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 3x2 | confidential in-proof | message bytes | 8679 | 10206 | 10130 | 1085 | 26 | 2 | 3 | buffered | buffer create 1 B |
| 3x2 | anonymous hidden | reply | 8568 | 10206 | 10169 | 989 | 23 | 2 | 3 | buffered | buffer create 1 B |
| 3x2 | anonymous hidden | messages | 249 | 10202 | 10164 | 989 | 23 | 2 | 3 | buffered | buffer create 30 B |
| 3x2 | anonymous hidden | message bytes | 8436 | 10206 | 10168 | 989 | 23 | 2 | 3 | buffered | buffer create 1 B |
| 3x2 | anonymous public owners | reply | 8632 | 10206 | 10136 | 1182 | 27 | 3 | 3 | buffered | buffer create 1 B |
| 3x2 | anonymous public owners | messages | 251 | 10206 | 10135 | 1182 | 27 | 3 | 3 | buffered | buffer create 34 B |
| 3x2 | anonymous public owners | message bytes | 8500 | 10206 | 10135 | 1182 | 27 | 3 | 3 | buffered | buffer create 1 B |
| 3x2 | confidential entry | messages | 241 | 10199 | 10122 | 1182 | 27 | 3 | 3 | buffered | buffer create 27 B |
| 3x2 | confidential entry | message bytes | 8167 | 10206 | 10129 | 1182 | 27 | 3 | 3 | buffered | buffer create 1 B |
| 3x2 | anonymous entry | reply | 7928 | 10206 | 10137 | 989 | 23 | 2 | 3 | buffered | buffer create 1 B |
| 3x2 | anonymous entry | messages | 230 | 10196 | 10126 | 989 | 23 | 2 | 3 | buffered | buffer create 24 B |
| 3x2 | anonymous entry | message bytes | 7796 | 10206 | 10136 | 989 | 23 | 2 | 3 | buffered | buffer create 1 B |
| 3x4 | confidential signer | messages | 240 | 10189 | 10180 | 1182 | 27 | 3 | 3 | buffered | buffer create 17 B |
| 3x4 | confidential signer | message bytes | 8143 | 10206 | 10197 | 1182 | 27 | 3 | 3 | buffered | buffer create 1 B |
| 3x4 | confidential in-proof | messages | 237 | 10183 | 10175 | 1085 | 26 | 2 | 3 | buffered | buffer create 11 B |
| 3x4 | confidential in-proof | message bytes | 8047 | 10206 | 10198 | 1085 | 26 | 2 | 3 | buffered | buffer create 1 B |
| 3x4 | anonymous hidden | reply | 2624 | 10206 | 10237 | 989 | 23 | 2 | 3 | buffered | buffer create 3 B |
| 3x4 | anonymous hidden | messages | 222 | 10174 | 10204 | 989 | 23 | 2 | 3 | buffered | buffer create 2 B |
| 3x4 | anonymous hidden | message bytes | 7546 | 10206 | 10236 | 989 | 23 | 2 | 3 | buffered | buffer create 1 B |
| 3x4 | anonymous public owners | reply | 2645 | 10205 | 10203 | 1182 | 27 | 3 | 3 | buffered | buffer create 2 B |
| 3x4 | anonymous public owners | messages | 224 | 10178 | 10175 | 1182 | 27 | 3 | 3 | buffered | buffer create 6 B |
| 3x4 | anonymous public owners | message bytes | 7610 | 10206 | 10203 | 1182 | 27 | 3 | 3 | buffered | buffer create 1 B |
| 3x4 | confidential entry | messages | 222 | 10185 | 10176 | 1182 | 27 | 3 | 3 | buffered | buffer create 13 B |
| 3x4 | confidential entry | message bytes | 7535 | 10206 | 10197 | 1182 | 27 | 3 | 3 | buffered | buffer create 1 B |
| 3x4 | anonymous entry | reply | 2410 | 10204 | 10203 | 989 | 23 | 2 | 3 | buffered | buffer create 1 B |
| 3x4 | anonymous entry | messages | 204 | 10202 | 10200 | 989 | 23 | 2 | 3 | buffered | buffer create 30 B |
| 3x4 | anonymous entry | message bytes | 6906 | 10206 | 10204 | 989 | 23 | 2 | 3 | buffered | buffer create 1 B |
| 2x16 | confidential signer | messages | 119 | 9837 | 10233 | 1149 | 26 | 3 | 3 | buffered | SPP CPI 27 B |
| 2x16 | confidential signer | message bytes | 4019 | 9844 | 10240 | 1149 | 26 | 3 | 3 | buffered | SPP CPI 1 B |
| 2x16 | confidential in-proof | messages | 116 | 9831 | 10228 | 1052 | 25 | 2 | 3 | buffered | SPP CPI 22 B |
| 2x16 | confidential in-proof | message bytes | 3922 | 9843 | 10240 | 1052 | 25 | 2 | 3 | buffered | SPP CPI 1 B |
| 2x16 | anonymous hidden | reply | 221 | 9795 | 10231 | 956 | 22 | 2 | 3 | buffered | SPP CPI 6 B |
| 2x16 | anonymous hidden | messages | 54 | 9772 | 10207 | 956 | 22 | 2 | 3 | buffered | SPP CPI 1 B |
| 2x16 | anonymous hidden | message bytes | 1835 | 9805 | 10240 | 956 | 22 | 2 | 3 | buffered | SPP CPI 1 B |
| 2x16 | anonymous public owners | reply | 228 | 9836 | 10239 | 1149 | 26 | 3 | 3 | buffered | SPP CPI 14 B |
| 2x16 | anonymous public owners | messages | 57 | 9810 | 10212 | 1149 | 26 | 3 | 3 | buffered | SPP CPI 6 B |
| 2x16 | anonymous public owners | message bytes | 1932 | 9838 | 10240 | 1149 | 26 | 3 | 3 | buffered | SPP CPI 1 B |
| 3x8 | confidential signer | messages | 200 | 10093 | 10220 | 1182 | 27 | 3 | 3 | buffered | SPP CPI 14 B |
| 3x8 | confidential signer | message bytes | 6786 | 10113 | 10240 | 1182 | 27 | 3 | 3 | buffered | SPP CPI 1 B |
| 3x8 | confidential in-proof | messages | 197 | 10087 | 10215 | 1085 | 26 | 2 | 3 | buffered | SPP CPI 9 B |
| 3x8 | confidential in-proof | message bytes | 6689 | 10112 | 10240 | 1085 | 26 | 2 | 3 | buffered | SPP CPI 1 B |
| 3x8 | anonymous hidden | reply | 906 | 10068 | 10235 | 989 | 23 | 2 | 3 | buffered | SPP CPI 2 B |
| 3x8 | anonymous hidden | messages | 166 | 10050 | 10216 | 989 | 23 | 2 | 3 | buffered | SPP CPI 10 B |
| 3x8 | anonymous hidden | message bytes | 5634 | 10074 | 10240 | 989 | 23 | 2 | 3 | buffered | SPP CPI 1 B |
| 3x8 | anonymous public owners | reply | 920 | 10102 | 10236 | 1182 | 27 | 3 | 3 | buffered | SPP CPI 3 B |
| 3x8 | anonymous public owners | messages | 169 | 10088 | 10221 | 1182 | 27 | 3 | 3 | buffered | SPP CPI 15 B |
| 3x8 | anonymous public owners | message bytes | 5731 | 10107 | 10240 | 1182 | 27 | 3 | 3 | buffered | SPP CPI 1 B |
| 3x8 | confidential entry | messages | 182 | 10089 | 10216 | 1182 | 27 | 3 | 3 | buffered | SPP CPI 10 B |
| 3x8 | confidential entry | message bytes | 6178 | 10113 | 10240 | 1182 | 27 | 3 | 3 | buffered | SPP CPI 1 B |
| 3x8 | anonymous entry | reply | 819 | 10099 | 10234 | 989 | 23 | 2 | 3 | buffered | SPP CPI 1 B |
| 3x8 | anonymous entry | messages | 148 | 10078 | 10212 | 989 | 23 | 2 | 3 | buffered | SPP CPI 6 B |
| 3x8 | anonymous entry | message bytes | 5026 | 10106 | 10240 | 989 | 23 | 2 | 3 | buffered | SPP CPI 1 B |
| 4x2 | confidential signer | messages | 254 | 10065 | 9989 | 1215 | 28 | 3 | 3 | buffered | confidential signer Shape { n_inputs: 4, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 4x2 | confidential signer | message bytes | 8743 | 10206 | 10130 | 1215 | 28 | 3 | 3 | buffered | buffer create 1 B |
| 4x2 | confidential in-proof | messages | 254 | 10161 | 10086 | 1118 | 27 | 2 | 3 | buffered | confidential in-proof Shape { n_inputs: 4, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 4x2 | confidential in-proof | message bytes | 8647 | 10206 | 10131 | 1118 | 27 | 2 | 3 | buffered | buffer create 1 B |
| 4x2 | anonymous hidden | reply | 8536 | 10206 | 10170 | 1022 | 24 | 2 | 3 | buffered | buffer create 1 B |
| 4x2 | anonymous hidden | messages | 248 | 10200 | 10163 | 1022 | 24 | 2 | 3 | buffered | buffer create 28 B |
| 4x2 | anonymous hidden | message bytes | 8404 | 10206 | 10169 | 1022 | 24 | 2 | 3 | buffered | buffer create 1 B |
| 4x2 | anonymous public owners | reply | 8600 | 10206 | 10137 | 1215 | 28 | 3 | 3 | buffered | buffer create 1 B |
| 4x2 | anonymous public owners | messages | 250 | 10204 | 10134 | 1215 | 28 | 3 | 3 | buffered | buffer create 32 B |
| 4x2 | anonymous public owners | message bytes | 8468 | 10206 | 10136 | 1215 | 28 | 3 | 3 | buffered | buffer create 1 B |
| 4x2 | confidential entry | messages | 234 | 10193 | 10117 | 1215 | 28 | 3 | 3 | buffered | buffer create 21 B |
| 4x2 | confidential entry | message bytes | 7935 | 10206 | 10130 | 1215 | 28 | 3 | 3 | buffered | buffer create 1 B |
| 4x2 | anonymous entry | reply | 7696 | 10206 | 10138 | 1022 | 24 | 2 | 3 | buffered | buffer create 1 B |
| 4x2 | anonymous entry | messages | 223 | 10190 | 10121 | 1022 | 24 | 2 | 3 | buffered | buffer create 18 B |
| 4x2 | anonymous entry | message bytes | 7564 | 10206 | 10137 | 1022 | 24 | 2 | 3 | buffered | buffer create 1 B |
| 4x4 | confidential signer | messages | 239 | 10187 | 10179 | 1215 | 28 | 3 | 3 | buffered | buffer create 15 B |
| 4x4 | confidential signer | message bytes | 8111 | 10206 | 10198 | 1215 | 28 | 3 | 3 | buffered | buffer create 1 B |
| 4x4 | confidential in-proof | messages | 236 | 10181 | 10174 | 1118 | 27 | 2 | 3 | buffered | buffer create 9 B |
| 4x4 | confidential in-proof | message bytes | 8015 | 10206 | 10199 | 1118 | 27 | 2 | 3 | buffered | buffer create 1 B |
| 4x4 | anonymous hidden | reply | 2613 | 10205 | 10237 | 1022 | 24 | 2 | 3 | buffered | buffer create 2 B |
| 4x4 | anonymous hidden | messages | 222 | 10206 | 10237 | 1022 | 24 | 2 | 3 | buffered | buffer create 34 B, SPP CPI 31 B |
| 4x4 | anonymous hidden | message bytes | 7514 | 10206 | 10237 | 1022 | 24 | 2 | 3 | buffered | buffer create 1 B |
| 4x4 | anonymous public owners | reply | 2634 | 10204 | 10203 | 1215 | 28 | 3 | 3 | buffered | buffer create 1 B |
| 4x4 | anonymous public owners | messages | 223 | 10176 | 10174 | 1215 | 28 | 3 | 3 | buffered | buffer create 4 B |
| 4x4 | anonymous public owners | message bytes | 7578 | 10206 | 10204 | 1215 | 28 | 3 | 3 | buffered | buffer create 1 B |
| 4x4 | confidential entry | messages | 215 | 10179 | 10171 | 1215 | 28 | 3 | 3 | buffered | buffer create 7 B |
| 4x4 | confidential entry | message bytes | 7303 | 10206 | 10198 | 1215 | 28 | 3 | 3 | buffered | buffer create 1 B |
| 4x4 | anonymous entry | reply | 2333 | 10205 | 10205 | 1022 | 24 | 2 | 3 | buffered | buffer create 2 B |
| 4x4 | anonymous entry | messages | 197 | 10196 | 10195 | 1022 | 24 | 2 | 3 | buffered | buffer create 24 B |
| 4x4 | anonymous entry | message bytes | 6674 | 10206 | 10205 | 1022 | 24 | 2 | 3 | buffered | buffer create 1 B |
| 4x4 | delegate | messages | 240 | 10165 | 10213 | 1019 | 24 | 2 | 3 | buffered | SPP CPI 7 B |
| 4x4 | delegate | message bytes | 8153 | 10192 | 10240 | 1019 | 24 | 2 | 3 | buffered | SPP CPI 1 B |
| 4x4 | anonymous delegate | reply | 2646 | 10184 | 10239 | 1019 | 24 | 2 | 3 | buffered | SPP CPI 2 B |
| 4x4 | anonymous delegate | messages | 224 | 10154 | 10208 | 1019 | 24 | 2 | 3 | buffered | SPP CPI 2 B |
| 4x4 | anonymous delegate | message bytes | 7614 | 10186 | 10240 | 1019 | 24 | 2 | 3 | buffered | SPP CPI 1 B |
| 4x8 | confidential signer | messages | 199 | 10091 | 10219 | 1215 | 28 | 3 | 3 | buffered | SPP CPI 13 B |
| 4x8 | confidential signer | message bytes | 6753 | 10112 | 10240 | 1215 | 28 | 3 | 3 | buffered | SPP CPI 1 B |
| 4x8 | confidential in-proof | messages | 196 | 10085 | 10214 | 1118 | 27 | 2 | 3 | buffered | SPP CPI 8 B |
| 4x8 | confidential in-proof | message bytes | 6656 | 10111 | 10240 | 1118 | 27 | 2 | 3 | buffered | SPP CPI 1 B |
| 4x8 | anonymous hidden | reply | 902 | 10072 | 10240 | 1022 | 24 | 2 | 3 | buffered | SPP CPI 7 B |
| 4x8 | anonymous hidden | messages | 165 | 10048 | 10215 | 1022 | 24 | 2 | 3 | buffered | SPP CPI 9 B |
| 4x8 | anonymous hidden | message bytes | 5601 | 10073 | 10240 | 1022 | 24 | 2 | 3 | buffered | SPP CPI 1 B |
| 4x8 | anonymous public owners | reply | 915 | 10099 | 10234 | 1215 | 28 | 3 | 3 | buffered | SPP CPI 1 B |
| 4x8 | anonymous public owners | messages | 168 | 10086 | 10220 | 1215 | 28 | 3 | 3 | buffered | SPP CPI 14 B |
| 4x8 | anonymous public owners | message bytes | 5698 | 10106 | 10240 | 1215 | 28 | 3 | 3 | buffered | SPP CPI 1 B |
| 4x8 | confidential entry | messages | 175 | 10083 | 10211 | 1215 | 28 | 3 | 3 | buffered | SPP CPI 5 B |
| 4x8 | confidential entry | message bytes | 5945 | 10112 | 10240 | 1215 | 28 | 3 | 3 | buffered | SPP CPI 1 B |
| 4x8 | anonymous entry | reply | 786 | 10100 | 10236 | 1022 | 24 | 2 | 3 | buffered | SPP CPI 3 B |
| 4x8 | anonymous entry | messages | 141 | 10072 | 10207 | 1022 | 24 | 2 | 3 | buffered | SPP CPI 1 B |
| 4x8 | anonymous entry | message bytes | 4793 | 10105 | 10240 | 1022 | 24 | 2 | 3 | buffered | SPP CPI 1 B |
| 5x2 | confidential signer | messages | 254 | 10097 | 10022 | 1248 | 29 | 3 | 3 | buffered | confidential signer Shape { n_inputs: 5, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 5x2 | confidential signer | message bytes | 8711 | 10206 | 10131 | 1248 | 29 | 3 | 3 | buffered | buffer create 1 B |
| 5x2 | confidential in-proof | messages | 254 | 10193 | 10119 | 1151 | 28 | 2 | 3 | buffered | confidential in-proof Shape { n_inputs: 5, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 5x2 | confidential in-proof | message bytes | 8615 | 10206 | 10132 | 1151 | 28 | 2 | 3 | buffered | buffer create 1 B |
| 5x2 | anonymous hidden | reply | 8504 | 10206 | 10171 | 1055 | 25 | 2 | 3 | buffered | buffer create 1 B |
| 5x2 | anonymous hidden | messages | 247 | 10198 | 10162 | 1055 | 25 | 2 | 3 | buffered | buffer create 26 B |
| 5x2 | anonymous hidden | message bytes | 8372 | 10206 | 10170 | 1055 | 25 | 2 | 3 | buffered | buffer create 1 B |
| 5x2 | anonymous public owners | reply | 8568 | 10206 | 10138 | 1248 | 29 | 3 | 3 | buffered | buffer create 1 B |
| 5x2 | anonymous public owners | messages | 249 | 10202 | 10133 | 1248 | 29 | 3 | 3 | buffered | buffer create 30 B |
| 5x2 | anonymous public owners | message bytes | 8436 | 10206 | 10137 | 1248 | 29 | 3 | 3 | buffered | buffer create 1 B |
| 5x2 | confidential entry | messages | 227 | 10187 | 10112 | 1248 | 29 | 3 | 3 | buffered | buffer create 15 B |
| 5x2 | confidential entry | message bytes | 7703 | 10206 | 10131 | 1248 | 29 | 3 | 3 | buffered | buffer create 1 B |
| 5x2 | anonymous entry | reply | 7464 | 10206 | 10139 | 1055 | 25 | 2 | 3 | buffered | buffer create 1 B |
| 5x2 | anonymous entry | messages | 216 | 10184 | 10116 | 1055 | 25 | 2 | 3 | buffered | buffer create 12 B |
| 5x2 | anonymous entry | message bytes | 7332 | 10206 | 10138 | 1055 | 25 | 2 | 3 | buffered | buffer create 1 B |
| 5x4 | confidential signer | messages | 238 | 10185 | 10178 | 1248 | 29 | 3 | 3 | buffered | buffer create 13 B |
| 5x4 | confidential signer | message bytes | 8079 | 10206 | 10199 | 1248 | 29 | 3 | 3 | buffered | buffer create 1 B |
| 5x4 | confidential in-proof | messages | 235 | 10179 | 10173 | 1151 | 28 | 2 | 3 | buffered | buffer create 7 B |
| 5x4 | confidential in-proof | message bytes | 7983 | 10206 | 10200 | 1151 | 28 | 2 | 3 | buffered | buffer create 1 B |
| 5x4 | anonymous hidden | reply | 2602 | 10204 | 10237 | 1055 | 25 | 2 | 3 | buffered | buffer create 1 B |
| 5x4 | anonymous hidden | messages | 221 | 10204 | 10236 | 1055 | 25 | 2 | 3 | buffered | buffer create 32 B, SPP CPI 30 B |
| 5x4 | anonymous hidden | message bytes | 7482 | 10206 | 10238 | 1055 | 25 | 2 | 3 | buffered | buffer create 1 B |
| 5x4 | anonymous public owners | reply | 2624 | 10206 | 10206 | 1248 | 29 | 3 | 3 | buffered | buffer create 3 B |
| 5x4 | anonymous public owners | messages | 222 | 10174 | 10173 | 1248 | 29 | 3 | 3 | buffered | buffer create 2 B |
| 5x4 | anonymous public owners | message bytes | 7546 | 10206 | 10205 | 1248 | 29 | 3 | 3 | buffered | buffer create 1 B |
| 5x4 | confidential entry | messages | 208 | 10173 | 10166 | 1248 | 29 | 3 | 3 | buffered | buffer create 1 B |
| 5x4 | confidential entry | message bytes | 7071 | 10206 | 10199 | 1248 | 29 | 3 | 3 | buffered | buffer create 1 B |
| 5x4 | anonymous entry | reply | 2256 | 10206 | 10207 | 1055 | 25 | 2 | 3 | buffered | buffer create 3 B |
| 5x4 | anonymous entry | messages | 190 | 10190 | 10190 | 1055 | 25 | 2 | 3 | buffered | buffer create 18 B |
| 5x4 | anonymous entry | message bytes | 6442 | 10206 | 10206 | 1055 | 25 | 2 | 3 | buffered | buffer create 1 B |
| 4x16 | confidential signer | messages | 117 | 9833 | 10231 | 1215 | 28 | 3 | 3 | buffered | SPP CPI 25 B |
| 4x16 | confidential signer | message bytes | 3953 | 9842 | 10240 | 1215 | 28 | 3 | 3 | buffered | SPP CPI 1 B |
| 4x16 | confidential in-proof | messages | 114 | 9827 | 10226 | 1118 | 27 | 2 | 3 | buffered | SPP CPI 20 B |
| 4x16 | confidential in-proof | message bytes | 3856 | 9841 | 10240 | 1118 | 27 | 2 | 3 | buffered | SPP CPI 1 B |
| 4x16 | anonymous hidden | reply | 217 | 9799 | 10237 | 1022 | 24 | 2 | 3 | buffered | SPP CPI 12 B |
| 4x16 | anonymous hidden | messages | 53 | 9802 | 10239 | 1022 | 24 | 2 | 3 | buffered | SPP CPI 33 B |
| 4x16 | anonymous hidden | message bytes | 1769 | 9803 | 10240 | 1022 | 24 | 2 | 3 | buffered | SPP CPI 1 B |
| 4x16 | anonymous public owners | reply | 223 | 9825 | 10230 | 1215 | 28 | 3 | 3 | buffered | SPP CPI 5 B |
| 4x16 | anonymous public owners | messages | 55 | 9806 | 10210 | 1215 | 28 | 3 | 3 | buffered | SPP CPI 4 B |
| 4x16 | anonymous public owners | message bytes | 1866 | 9836 | 10240 | 1215 | 28 | 3 | 3 | buffered | SPP CPI 1 B |
| 5x8 | confidential signer | messages | 198 | 10089 | 10218 | 1248 | 29 | 3 | 3 | buffered | SPP CPI 12 B |
| 5x8 | confidential signer | message bytes | 6720 | 10111 | 10240 | 1248 | 29 | 3 | 3 | buffered | SPP CPI 1 B |
| 5x8 | confidential in-proof | messages | 195 | 10083 | 10213 | 1151 | 28 | 2 | 3 | buffered | SPP CPI 7 B |
| 5x8 | confidential in-proof | message bytes | 6623 | 10110 | 10240 | 1151 | 28 | 2 | 3 | buffered | SPP CPI 1 B |
| 5x8 | anonymous hidden | reply | 897 | 10069 | 10238 | 1055 | 25 | 2 | 3 | buffered | SPP CPI 5 B |
| 5x8 | anonymous hidden | messages | 164 | 10046 | 10214 | 1055 | 25 | 2 | 3 | buffered | SPP CPI 8 B |
| 5x8 | anonymous hidden | message bytes | 5568 | 10072 | 10240 | 1055 | 25 | 2 | 3 | buffered | SPP CPI 1 B |
| 5x8 | anonymous public owners | reply | 911 | 10103 | 10239 | 1248 | 29 | 3 | 3 | buffered | SPP CPI 6 B |
| 5x8 | anonymous public owners | messages | 167 | 10084 | 10219 | 1248 | 29 | 3 | 3 | buffered | SPP CPI 13 B |
| 5x8 | anonymous public owners | message bytes | 5665 | 10105 | 10240 | 1248 | 29 | 3 | 3 | buffered | SPP CPI 1 B |
| 6x2 | confidential signer | messages | 254 | 10129 | 10055 | 1281 | 30 | 3 | 3 | buffered | confidential signer Shape { n_inputs: 6, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 6x2 | confidential signer | message bytes | 8679 | 10206 | 10132 | 1281 | 30 | 3 | 3 | buffered | buffer create 1 B |
| 6x2 | confidential in-proof | messages | 253 | 10191 | 10118 | 1184 | 29 | 2 | 3 | buffered | buffer create 19 B |
| 6x2 | confidential in-proof | message bytes | 8583 | 10206 | 10133 | 1184 | 29 | 2 | 3 | buffered | buffer create 1 B |
| 6x2 | anonymous hidden | reply | 8472 | 10206 | 10172 | 1088 | 26 | 2 | 3 | buffered | buffer create 1 B |
| 6x2 | anonymous hidden | messages | 246 | 10196 | 10161 | 1088 | 26 | 2 | 3 | buffered | buffer create 24 B |
| 6x2 | anonymous hidden | message bytes | 8340 | 10206 | 10171 | 1088 | 26 | 2 | 3 | buffered | buffer create 1 B |
| 6x2 | anonymous public owners | reply | 8536 | 10206 | 10139 | 1281 | 30 | 3 | 3 | buffered | buffer create 1 B |
| 6x2 | anonymous public owners | messages | 248 | 10200 | 10132 | 1281 | 30 | 3 | 3 | buffered | buffer create 28 B |
| 6x2 | anonymous public owners | message bytes | 8404 | 10206 | 10138 | 1281 | 30 | 3 | 3 | buffered | buffer create 1 B |
| 6x2 | confidential entry | messages | 220 | 10181 | 10107 | 1281 | 30 | 3 | 3 | buffered | buffer create 9 B |
| 6x2 | confidential entry | message bytes | 7471 | 10206 | 10132 | 1281 | 30 | 3 | 3 | buffered | buffer create 1 B |
| 6x2 | anonymous entry | reply | 7232 | 10206 | 10140 | 1088 | 26 | 2 | 3 | buffered | buffer create 1 B |
| 6x2 | anonymous entry | messages | 209 | 10178 | 10111 | 1088 | 26 | 2 | 3 | buffered | buffer create 6 B |
| 6x2 | anonymous entry | message bytes | 7100 | 10206 | 10139 | 1088 | 26 | 2 | 3 | buffered | buffer create 1 B |
| 6x4 | confidential signer | messages | 237 | 10183 | 10177 | 1281 | 30 | 3 | 3 | buffered | buffer create 11 B |
| 6x4 | confidential signer | message bytes | 8047 | 10206 | 10200 | 1281 | 30 | 3 | 3 | buffered | buffer create 1 B |
| 6x4 | confidential in-proof | messages | 234 | 10177 | 10172 | 1184 | 29 | 2 | 3 | buffered | buffer create 5 B |
| 6x4 | confidential in-proof | message bytes | 7951 | 10206 | 10201 | 1184 | 29 | 2 | 3 | buffered | buffer create 1 B |
| 6x4 | anonymous hidden | reply | 2592 | 10206 | 10240 | 1088 | 26 | 2 | 3 | buffered | buffer create 3 B, SPP CPI 3 B |
| 6x4 | anonymous hidden | messages | 220 | 10202 | 10235 | 1088 | 26 | 2 | 3 | buffered | buffer create 30 B, SPP CPI 29 B |
| 6x4 | anonymous hidden | message bytes | 7450 | 10206 | 10239 | 1088 | 26 | 2 | 3 | buffered | buffer create 1 B |
| 6x4 | anonymous public owners | reply | 2613 | 10205 | 10206 | 1281 | 30 | 3 | 3 | buffered | buffer create 2 B |
| 6x4 | anonymous public owners | messages | 222 | 10206 | 10206 | 1281 | 30 | 3 | 3 | buffered | buffer create 34 B |
| 6x4 | anonymous public owners | message bytes | 7514 | 10206 | 10206 | 1281 | 30 | 3 | 3 | buffered | buffer create 1 B |
| 6x4 | confidential entry | messages | 202 | 10201 | 10195 | 1281 | 30 | 3 | 3 | buffered | buffer create 29 B |
| 6x4 | confidential entry | message bytes | 6839 | 10206 | 10200 | 1281 | 30 | 3 | 3 | buffered | buffer create 1 B |
| 6x4 | anonymous entry | reply | 2178 | 10204 | 10206 | 1088 | 26 | 2 | 3 | buffered | buffer create 1 B |
| 6x4 | anonymous entry | messages | 183 | 10184 | 10185 | 1088 | 26 | 2 | 3 | buffered | buffer create 12 B |
| 6x4 | anonymous entry | message bytes | 6210 | 10206 | 10207 | 1088 | 26 | 2 | 3 | buffered | buffer create 1 B |
| 5x16 | confidential signer | messages | 116 | 9831 | 10230 | 1248 | 29 | 3 | 3 | buffered | SPP CPI 24 B |
| 5x16 | confidential signer | message bytes | 3920 | 9841 | 10240 | 1248 | 29 | 3 | 3 | buffered | SPP CPI 1 B |
| 5x16 | confidential in-proof | messages | 113 | 9825 | 10225 | 1151 | 28 | 2 | 3 | buffered | SPP CPI 19 B |
| 5x16 | confidential in-proof | message bytes | 3823 | 9840 | 10240 | 1151 | 28 | 2 | 3 | buffered | SPP CPI 1 B |
| 5x16 | anonymous hidden | reply | 215 | 9801 | 10240 | 1055 | 25 | 2 | 3 | buffered | SPP CPI 15 B |
| 5x16 | anonymous hidden | messages | 52 | 9800 | 10238 | 1055 | 25 | 2 | 3 | buffered | SPP CPI 32 B |
| 5x16 | anonymous hidden | message bytes | 1736 | 9802 | 10240 | 1055 | 25 | 2 | 3 | buffered | SPP CPI 1 B |
| 5x16 | anonymous public owners | reply | 221 | 9827 | 10233 | 1248 | 29 | 3 | 3 | buffered | SPP CPI 8 B |
| 5x16 | anonymous public owners | messages | 54 | 9804 | 10209 | 1248 | 29 | 3 | 3 | buffered | SPP CPI 3 B |
| 5x16 | anonymous public owners | message bytes | 1833 | 9835 | 10240 | 1248 | 29 | 3 | 3 | buffered | SPP CPI 1 B |
| 6x8 | confidential signer | messages | 197 | 10087 | 10217 | 1281 | 30 | 3 | 3 | buffered | SPP CPI 11 B |
| 6x8 | confidential signer | message bytes | 6687 | 10110 | 10240 | 1281 | 30 | 3 | 3 | buffered | SPP CPI 1 B |
| 6x8 | confidential in-proof | messages | 194 | 10081 | 10212 | 1184 | 29 | 2 | 3 | buffered | SPP CPI 6 B |
| 6x8 | confidential in-proof | message bytes | 6590 | 10109 | 10240 | 1184 | 29 | 2 | 3 | buffered | SPP CPI 1 B |
| 6x8 | anonymous hidden | reply | 892 | 10066 | 10236 | 1088 | 26 | 2 | 3 | buffered | SPP CPI 3 B |
| 6x8 | anonymous hidden | messages | 163 | 10044 | 10213 | 1088 | 26 | 2 | 3 | buffered | SPP CPI 7 B |
| 6x8 | anonymous hidden | message bytes | 5535 | 10071 | 10240 | 1088 | 26 | 2 | 3 | buffered | SPP CPI 1 B |
| 6x8 | anonymous public owners | reply | 906 | 10100 | 10237 | 1281 | 30 | 3 | 3 | buffered | SPP CPI 4 B |
| 6x8 | anonymous public owners | messages | 166 | 10082 | 10218 | 1281 | 30 | 3 | 3 | buffered | SPP CPI 12 B |
| 6x8 | anonymous public owners | message bytes | 5632 | 10104 | 10240 | 1281 | 30 | 3 | 3 | buffered | SPP CPI 1 B |
| 8x2 | confidential signer | messages | 254 | 10193 | 10121 | 1347 | 32 | 3 | 3 | buffered | confidential signer Shape { n_inputs: 8, n_outputs: 2 }: application messages exceed what SPP takes beside the auditor message and the sender bundle |
| 8x2 | confidential signer | message bytes | 8615 | 10206 | 10134 | 1347 | 32 | 3 | 3 | buffered | buffer create 1 B |
| 8x2 | confidential in-proof | messages | 251 | 10187 | 10116 | 1250 | 31 | 2 | 3 | buffered | buffer create 15 B |
| 8x2 | confidential in-proof | message bytes | 8519 | 10206 | 10135 | 1250 | 31 | 2 | 3 | buffered | buffer create 1 B |
| 8x2 | anonymous hidden | reply | 8408 | 10206 | 10174 | 1154 | 28 | 2 | 3 | buffered | buffer create 1 B |
| 8x2 | anonymous hidden | messages | 244 | 10192 | 10159 | 1154 | 28 | 2 | 3 | buffered | buffer create 20 B |
| 8x2 | anonymous hidden | message bytes | 8276 | 10206 | 10173 | 1154 | 28 | 2 | 3 | buffered | buffer create 1 B |
| 8x2 | anonymous public owners | reply | 8472 | 10206 | 10141 | 1347 | 32 | 3 | 3 | buffered | buffer create 1 B |
| 8x2 | anonymous public owners | messages | 246 | 10196 | 10130 | 1347 | 32 | 3 | 3 | buffered | buffer create 24 B |
| 8x2 | anonymous public owners | message bytes | 8340 | 10206 | 10140 | 1347 | 32 | 3 | 3 | buffered | buffer create 1 B |
| 8x2 | confidential entry | messages | 207 | 10203 | 10131 | 1347 | 32 | 3 | 3 | buffered | buffer create 31 B |
| 8x2 | confidential entry | message bytes | 7007 | 10206 | 10134 | 1347 | 32 | 3 | 3 | buffered | buffer create 1 B |
| 8x2 | anonymous entry | reply | 6768 | 10206 | 10142 | 1154 | 28 | 2 | 3 | buffered | buffer create 1 B |
| 8x2 | anonymous entry | messages | 196 | 10200 | 10135 | 1154 | 28 | 2 | 3 | buffered | buffer create 28 B |
| 8x2 | anonymous entry | message bytes | 6636 | 10206 | 10141 | 1154 | 28 | 2 | 3 | buffered | buffer create 1 B |
| 8x4 | confidential signer | messages | 235 | 10179 | 10175 | 1347 | 32 | 3 | 3 | buffered | buffer create 7 B |
| 8x4 | confidential signer | message bytes | 7983 | 10206 | 10202 | 1347 | 32 | 3 | 3 | buffered | buffer create 1 B |
| 8x4 | confidential in-proof | messages | 232 | 10173 | 10170 | 1250 | 31 | 2 | 3 | buffered | buffer create 1 B |
| 8x4 | confidential in-proof | message bytes | 7887 | 10206 | 10203 | 1250 | 31 | 2 | 3 | buffered | buffer create 1 B |
| 8x4 | anonymous hidden | reply | 2570 | 10204 | 10240 | 1154 | 28 | 2 | 3 | buffered | buffer create 1 B, SPP CPI 3 B |
| 8x4 | anonymous hidden | messages | 218 | 10198 | 10233 | 1154 | 28 | 2 | 3 | buffered | buffer create 26 B, SPP CPI 27 B |
| 8x4 | anonymous hidden | message bytes | 7385 | 10205 | 10240 | 1154 | 28 | 2 | 3 | buffered | SPP CPI 1 B |
| 8x4 | anonymous public owners | reply | 2592 | 10206 | 10209 | 1347 | 32 | 3 | 3 | buffered | buffer create 3 B |
| 8x4 | anonymous public owners | messages | 220 | 10202 | 10204 | 1347 | 32 | 3 | 3 | buffered | buffer create 30 B |
| 8x4 | anonymous public owners | message bytes | 7450 | 10206 | 10208 | 1347 | 32 | 3 | 3 | buffered | buffer create 1 B |
| 8x4 | confidential entry | messages | 188 | 10189 | 10185 | 1347 | 32 | 3 | 3 | buffered | buffer create 17 B |
| 8x4 | confidential entry | message bytes | 6375 | 10206 | 10202 | 1347 | 32 | 3 | 3 | buffered | buffer create 1 B |
| 8x4 | anonymous entry | reply | 2024 | 10206 | 10210 | 1154 | 28 | 2 | 3 | buffered | buffer create 3 B |
| 8x4 | anonymous entry | messages | 170 | 10206 | 10209 | 1154 | 28 | 2 | 3 | buffered | buffer create 34 B, SPP CPI 3 B |
| 8x4 | anonymous entry | message bytes | 5746 | 10206 | 10209 | 1154 | 28 | 2 | 3 | buffered | buffer create 1 B |
| 8x8 | confidential signer | messages | 195 | 10083 | 10215 | 1347 | 32 | 3 | 3 | buffered | SPP CPI 9 B |
| 8x8 | confidential signer | message bytes | 6621 | 10108 | 10240 | 1347 | 32 | 3 | 3 | buffered | SPP CPI 1 B |
| 8x8 | confidential in-proof | messages | 192 | 10077 | 10210 | 1250 | 31 | 2 | 3 | buffered | SPP CPI 4 B |
| 8x8 | confidential in-proof | message bytes | 6524 | 10107 | 10240 | 1250 | 31 | 2 | 3 | buffered | SPP CPI 1 B |
| 8x8 | anonymous hidden | reply | 883 | 10067 | 10239 | 1154 | 28 | 2 | 3 | buffered | SPP CPI 6 B |
| 8x8 | anonymous hidden | messages | 161 | 10040 | 10211 | 1154 | 28 | 2 | 3 | buffered | SPP CPI 5 B |
| 8x8 | anonymous hidden | message bytes | 5469 | 10069 | 10240 | 1154 | 28 | 2 | 3 | buffered | SPP CPI 1 B |
| 8x8 | anonymous public owners | reply | 897 | 10101 | 10240 | 1347 | 32 | 3 | 3 | buffered | SPP CPI 7 B |
| 8x8 | anonymous public owners | messages | 164 | 10078 | 10216 | 1347 | 32 | 3 | 3 | buffered | SPP CPI 10 B |
| 8x8 | anonymous public owners | message bytes | 5566 | 10102 | 10240 | 1347 | 32 | 3 | 3 | buffered | SPP CPI 1 B |
| 8x16 | confidential signer | messages | 113 | 9825 | 10227 | 1347 | 32 | 3 | 3 | buffered | SPP CPI 21 B |
| 8x16 | confidential signer | message bytes | 3821 | 9838 | 10240 | 1347 | 32 | 3 | 3 | buffered | SPP CPI 1 B |
| 8x16 | confidential in-proof | messages | 110 | 9819 | 10222 | 1250 | 31 | 2 | 3 | buffered | SPP CPI 16 B |
| 8x16 | confidential in-proof | message bytes | 3724 | 9837 | 10240 | 1250 | 31 | 2 | 3 | buffered | SPP CPI 1 B |
| 8x16 | anonymous hidden | reply | 208 | 9792 | 10234 | 1154 | 28 | 2 | 3 | buffered | SPP CPI 9 B |
| 8x16 | anonymous hidden | messages | 49 | 9794 | 10235 | 1154 | 28 | 2 | 3 | buffered | SPP CPI 29 B |
| 8x16 | anonymous hidden | message bytes | 1637 | 9799 | 10240 | 1154 | 28 | 2 | 3 | buffered | SPP CPI 1 B |
| 8x16 | anonymous public owners | reply | 214 | 9818 | 10227 | 1347 | 32 | 3 | 3 | buffered | SPP CPI 2 B |
| 8x16 | anonymous public owners | messages | 52 | 9832 | 10240 | 1347 | 32 | 3 | 3 | buffered | SPP CPI 34 B |
| 8x16 | anonymous public owners | message bytes | 1734 | 9832 | 10240 | 1347 | 32 | 3 | 3 | buffered | SPP CPI 1 B |
| 12x2 | confidential signer | messages | 250 | 10186 | 10117 | 1479 | 36 | 3 | 3 | buffered | buffer create 14 B |
| 12x2 | confidential signer | message bytes | 8486 | 10206 | 10137 | 1479 | 36 | 3 | 3 | buffered | buffer create 1 B |
| 12x2 | confidential in-proof | messages | 247 | 10180 | 10112 | 1382 | 35 | 2 | 3 | buffered | buffer create 8 B |
| 12x2 | confidential in-proof | message bytes | 8390 | 10206 | 10138 | 1382 | 35 | 2 | 3 | buffered | buffer create 1 B |
| 12x2 | anonymous hidden | reply | 8279 | 10206 | 10177 | 1286 | 32 | 2 | 3 | buffered | buffer create 1 B |
| 12x2 | anonymous hidden | messages | 240 | 10185 | 10155 | 1286 | 32 | 2 | 3 | buffered | buffer create 13 B |
| 12x2 | anonymous hidden | message bytes | 8147 | 10206 | 10176 | 1286 | 32 | 2 | 3 | buffered | buffer create 1 B |
| 12x2 | anonymous public owners | reply | 8343 | 10206 | 10144 | 1479 | 36 | 3 | 3 | buffered | buffer create 1 B |
| 12x2 | anonymous public owners | messages | 242 | 10189 | 10126 | 1479 | 36 | 3 | 3 | buffered | buffer create 17 B |
| 12x2 | anonymous public owners | message bytes | 8211 | 10206 | 10143 | 1479 | 36 | 3 | 3 | buffered | buffer create 1 B |
| 12x2 | confidential entry | messages | 179 | 10180 | 10111 | 1479 | 36 | 3 | 3 | buffered | buffer create 8 B |
| 12x2 | confidential entry | message bytes | 6078 | 10206 | 10137 | 1479 | 36 | 3 | 3 | buffered | buffer create 1 B |
| 12x2 | anonymous entry | reply | 5839 | 10206 | 10145 | 1286 | 32 | 2 | 3 | buffered | buffer create 1 B |
| 12x2 | anonymous entry | messages | 168 | 10177 | 10115 | 1286 | 32 | 2 | 3 | buffered | buffer create 5 B |
| 12x2 | anonymous entry | message bytes | 5707 | 10206 | 10144 | 1286 | 32 | 2 | 3 | buffered | buffer create 1 B |
| 12x4 | confidential signer | messages | 232 | 10206 | 10205 | 1479 | 36 | 3 | 3 | buffered | buffer create 34 B |
| 12x4 | confidential signer | message bytes | 7854 | 10206 | 10205 | 1479 | 36 | 3 | 3 | buffered | buffer create 1 B |
| 12x4 | confidential in-proof | messages | 229 | 10200 | 10200 | 1382 | 35 | 2 | 3 | buffered | buffer create 28 B |
| 12x4 | confidential in-proof | message bytes | 7758 | 10206 | 10206 | 1382 | 35 | 2 | 3 | buffered | buffer create 1 B |
| 12x4 | anonymous hidden | reply | 2526 | 10201 | 10240 | 1286 | 32 | 2 | 3 | buffered | SPP CPI 3 B |
| 12x4 | anonymous hidden | messages | 214 | 10191 | 10229 | 1286 | 32 | 2 | 3 | buffered | buffer create 19 B, SPP CPI 23 B |
| 12x4 | anonymous hidden | message bytes | 7253 | 10202 | 10240 | 1286 | 32 | 2 | 3 | buffered | SPP CPI 1 B |
| 12x4 | anonymous public owners | reply | 2549 | 10206 | 10212 | 1479 | 36 | 3 | 3 | buffered | buffer create 3 B |
| 12x4 | anonymous public owners | messages | 216 | 10195 | 10200 | 1479 | 36 | 3 | 3 | buffered | buffer create 23 B |
| 12x4 | anonymous public owners | message bytes | 7321 | 10206 | 10211 | 1479 | 36 | 3 | 3 | buffered | buffer create 1 B |
| 12x8 | confidential signer | messages | 191 | 10076 | 10211 | 1479 | 36 | 3 | 3 | buffered | SPP CPI 5 B |
| 12x8 | confidential signer | message bytes | 6489 | 10105 | 10240 | 1479 | 36 | 3 | 3 | buffered | SPP CPI 1 B |
| 12x8 | confidential in-proof | messages | 189 | 10104 | 10240 | 1382 | 35 | 2 | 3 | buffered | SPP CPI 34 B |
| 12x8 | confidential in-proof | message bytes | 6392 | 10104 | 10240 | 1382 | 35 | 2 | 3 | buffered | SPP CPI 1 B |
| 12x8 | anonymous hidden | reply | 864 | 10063 | 10238 | 1286 | 32 | 2 | 3 | buffered | SPP CPI 5 B |
| 12x8 | anonymous hidden | messages | 157 | 10033 | 10207 | 1286 | 32 | 2 | 3 | buffered | SPP CPI 1 B |
| 12x8 | anonymous hidden | message bytes | 5337 | 10066 | 10240 | 1286 | 32 | 2 | 3 | buffered | SPP CPI 1 B |
| 12x8 | anonymous public owners | reply | 878 | 10097 | 10239 | 1479 | 36 | 3 | 3 | buffered | SPP CPI 6 B |
| 12x8 | anonymous public owners | messages | 160 | 10071 | 10212 | 1479 | 36 | 3 | 3 | buffered | SPP CPI 6 B |
| 12x8 | anonymous public owners | message bytes | 5434 | 10099 | 10240 | 1479 | 36 | 3 | 3 | buffered | SPP CPI 1 B |
| 16x2 | confidential signer | messages | 246 | 10178 | 10113 | 1611 | 40 | 3 | 3 | buffered | buffer create 6 B |
| 16x2 | confidential signer | message bytes | 8358 | 10206 | 10141 | 1611 | 40 | 3 | 3 | buffered | buffer create 1 B |
| 16x2 | confidential in-proof | messages | 244 | 10206 | 10142 | 1514 | 39 | 2 | 3 | buffered | buffer create 34 B |
| 16x2 | confidential in-proof | message bytes | 8262 | 10206 | 10142 | 1514 | 39 | 2 | 3 | buffered | buffer create 1 B |
| 16x2 | anonymous hidden | reply | 8151 | 10206 | 10181 | 1418 | 36 | 2 | 3 | buffered | buffer create 1 B |
| 16x2 | anonymous hidden | messages | 236 | 10177 | 10151 | 1418 | 36 | 2 | 3 | buffered | buffer create 5 B |
| 16x2 | anonymous hidden | message bytes | 8019 | 10206 | 10180 | 1418 | 36 | 2 | 3 | buffered | buffer create 1 B |
| 16x2 | anonymous public owners | reply | 8215 | 10206 | 10148 | 1611 | 40 | 3 | 3 | buffered | buffer create 1 B |
| 16x2 | anonymous public owners | messages | 238 | 10181 | 10122 | 1611 | 40 | 3 | 3 | buffered | buffer create 9 B |
| 16x2 | anonymous public owners | message bytes | 8083 | 10206 | 10147 | 1611 | 40 | 3 | 3 | buffered | buffer create 1 B |
| 16x2 | confidential entry | messages | 152 | 10190 | 10125 | 1611 | 40 | 3 | 3 | buffered | buffer create 18 B |
| 16x2 | confidential entry | message bytes | 5150 | 10206 | 10141 | 1611 | 40 | 3 | 3 | buffered | buffer create 1 B |
| 16x2 | anonymous entry | reply | 4911 | 10206 | 10149 | 1418 | 36 | 2 | 3 | buffered | buffer create 1 B |
| 16x2 | anonymous entry | messages | 141 | 10187 | 10129 | 1418 | 36 | 2 | 3 | buffered | buffer create 15 B |
| 16x2 | anonymous entry | message bytes | 4779 | 10206 | 10148 | 1418 | 36 | 2 | 3 | buffered | buffer create 1 B |
| 16x4 | confidential signer | messages | 228 | 10198 | 10201 | 1611 | 40 | 3 | 3 | buffered | buffer create 26 B |
| 16x4 | confidential signer | message bytes | 7726 | 10206 | 10209 | 1611 | 40 | 3 | 3 | buffered | buffer create 1 B |
| 16x4 | confidential in-proof | messages | 225 | 10192 | 10196 | 1514 | 39 | 2 | 3 | buffered | buffer create 20 B |
| 16x4 | confidential in-proof | message bytes | 7630 | 10206 | 10210 | 1514 | 39 | 2 | 3 | buffered | buffer create 1 B |
| 16x4 | anonymous hidden | reply | 2482 | 10197 | 10240 | 1418 | 36 | 2 | 3 | buffered | SPP CPI 3 B |
| 16x4 | anonymous hidden | messages | 210 | 10183 | 10225 | 1418 | 36 | 2 | 3 | buffered | buffer create 11 B, SPP CPI 19 B |
| 16x4 | anonymous hidden | message bytes | 7121 | 10198 | 10240 | 1418 | 36 | 2 | 3 | buffered | SPP CPI 1 B |
| 16x4 | anonymous public owners | reply | 2506 | 10205 | 10215 | 1611 | 40 | 3 | 3 | buffered | buffer create 2 B |
| 16x4 | anonymous public owners | messages | 212 | 10187 | 10196 | 1611 | 40 | 3 | 3 | buffered | buffer create 15 B |
| 16x4 | anonymous public owners | message bytes | 7193 | 10206 | 10215 | 1611 | 40 | 3 | 3 | buffered | buffer create 1 B |
| 16x8 | confidential signer | messages | 187 | 10068 | 10207 | 1611 | 40 | 3 | 3 | buffered | SPP CPI 1 B |
| 16x8 | confidential signer | message bytes | 6357 | 10101 | 10240 | 1611 | 40 | 3 | 3 | buffered | SPP CPI 1 B |
| 16x8 | confidential in-proof | messages | 185 | 10096 | 10236 | 1514 | 39 | 2 | 3 | buffered | SPP CPI 30 B |
| 16x8 | confidential in-proof | message bytes | 6260 | 10100 | 10240 | 1514 | 39 | 2 | 3 | buffered | SPP CPI 1 B |
| 16x8 | anonymous hidden | reply | 845 | 10058 | 10237 | 1418 | 36 | 2 | 3 | buffered | SPP CPI 4 B |
| 16x8 | anonymous hidden | messages | 154 | 10059 | 10237 | 1418 | 36 | 2 | 3 | buffered | SPP CPI 31 B |
| 16x8 | anonymous hidden | message bytes | 5205 | 10062 | 10240 | 1418 | 36 | 2 | 3 | buffered | SPP CPI 1 B |
| 16x8 | anonymous public owners | reply | 859 | 10092 | 10238 | 1611 | 40 | 3 | 3 | buffered | SPP CPI 5 B |
| 16x8 | anonymous public owners | messages | 156 | 10063 | 10208 | 1611 | 40 | 3 | 3 | buffered | SPP CPI 2 B |
| 16x8 | anonymous public owners | message bytes | 5302 | 10095 | 10240 | 1611 | 40 | 3 | 3 | buffered | SPP CPI 1 B |
| 24x2 | confidential signer | messages | 239 | 10197 | 10139 | 1875 | 48 | 3 | 3 | buffered | buffer create 25 B |
| 24x2 | confidential signer | message bytes | 8101 | 10206 | 10148 | 1875 | 48 | 3 | 3 | buffered | buffer create 1 B |
| 24x2 | confidential in-proof | messages | 236 | 10191 | 10134 | 1778 | 47 | 2 | 3 | buffered | buffer create 19 B |
| 24x2 | confidential in-proof | message bytes | 8005 | 10206 | 10149 | 1778 | 47 | 2 | 3 | buffered | buffer create 1 B |
| 24x2 | anonymous hidden | reply | 7894 | 10206 | 10188 | 1682 | 44 | 2 | 3 | buffered | buffer create 1 B |
| 24x2 | anonymous hidden | messages | 229 | 10196 | 10177 | 1682 | 44 | 2 | 3 | buffered | buffer create 24 B |
| 24x2 | anonymous hidden | message bytes | 7762 | 10206 | 10187 | 1682 | 44 | 2 | 3 | buffered | buffer create 1 B |
| 24x2 | anonymous public owners | reply | 7958 | 10206 | 10155 | 1875 | 48 | 3 | 3 | buffered | buffer create 1 B |
| 24x2 | anonymous public owners | messages | 231 | 10200 | 10148 | 1875 | 48 | 3 | 3 | buffered | buffer create 28 B |
| 24x2 | anonymous public owners | message bytes | 7826 | 10206 | 10154 | 1875 | 48 | 3 | 3 | buffered | buffer create 1 B |
| 24x2 | confidential entry | messages | 97 | 10177 | 10119 | 1875 | 48 | 3 | 3 | buffered | buffer create 5 B |
| 24x2 | confidential entry | message bytes | 3293 | 10206 | 10148 | 1875 | 48 | 3 | 3 | buffered | buffer create 1 B |
| 24x2 | anonymous entry | reply | 3054 | 10206 | 10156 | 1682 | 44 | 2 | 3 | buffered | buffer create 1 B |
| 24x2 | anonymous entry | messages | 86 | 10174 | 10123 | 1682 | 44 | 2 | 3 | buffered | buffer create 2 B |
| 24x2 | anonymous entry | message bytes | 2922 | 10206 | 10155 | 1682 | 44 | 2 | 3 | buffered | buffer create 1 B |
| 24x4 | confidential signer | messages | 220 | 10183 | 10193 | 1875 | 48 | 3 | 3 | buffered | buffer create 11 B |
| 24x4 | confidential signer | message bytes | 7469 | 10206 | 10216 | 1875 | 48 | 3 | 3 | buffered | buffer create 1 B |
| 24x4 | confidential in-proof | messages | 217 | 10177 | 10188 | 1778 | 47 | 2 | 3 | buffered | buffer create 5 B |
| 24x4 | confidential in-proof | message bytes | 7373 | 10206 | 10217 | 1778 | 47 | 2 | 3 | buffered | buffer create 1 B |
| 24x4 | anonymous hidden | reply | 2394 | 10190 | 10240 | 1682 | 44 | 2 | 3 | buffered | SPP CPI 3 B |
| 24x4 | anonymous hidden | messages | 202 | 10168 | 10217 | 1682 | 44 | 2 | 3 | buffered | SPP CPI 11 B |
| 24x4 | anonymous hidden | message bytes | 6857 | 10191 | 10240 | 1682 | 44 | 2 | 3 | buffered | SPP CPI 1 B |
| 24x4 | anonymous public owners | reply | 2420 | 10204 | 10221 | 1875 | 48 | 3 | 3 | buffered | buffer create 1 B |
| 24x4 | anonymous public owners | messages | 205 | 10206 | 10222 | 1875 | 48 | 3 | 3 | buffered | buffer create 34 B, SPP CPI 16 B |
| 24x4 | anonymous public owners | message bytes | 6936 | 10206 | 10222 | 1875 | 48 | 3 | 3 | buffered | buffer create 1 B |
| 32x2 | confidential signer | messages | 231 | 10182 | 10131 | 2139 | 56 | 3 | 3 | buffered | buffer create 10 B |
| 32x2 | confidential signer | message bytes | 7844 | 10206 | 10155 | 2139 | 56 | 3 | 3 | buffered | buffer create 1 B |
| 32x2 | confidential in-proof | messages | 228 | 10176 | 10126 | 2042 | 55 | 2 | 3 | buffered | buffer create 4 B |
| 32x2 | confidential in-proof | message bytes | 7748 | 10206 | 10156 | 2042 | 55 | 2 | 3 | buffered | buffer create 1 B |
| 32x2 | anonymous hidden | reply | 7637 | 10206 | 10195 | 1946 | 52 | 2 | 3 | buffered | buffer create 1 B |
| 32x2 | anonymous hidden | messages | 221 | 10181 | 10169 | 1946 | 52 | 2 | 3 | buffered | buffer create 9 B |
| 32x2 | anonymous hidden | message bytes | 7505 | 10206 | 10194 | 1946 | 52 | 2 | 3 | buffered | buffer create 1 B |
| 32x2 | anonymous public owners | reply | 7701 | 10206 | 10162 | 2139 | 56 | 3 | 3 | buffered | buffer create 1 B |
| 32x2 | anonymous public owners | messages | 223 | 10185 | 10140 | 2139 | 56 | 3 | 3 | buffered | buffer create 13 B |
| 32x2 | anonymous public owners | message bytes | 7569 | 10206 | 10161 | 2139 | 56 | 3 | 3 | buffered | buffer create 1 B |
| 40x2 | confidential signer | messages | 224 | 10201 | 10157 | 2403 | 64 | 3 | 3 | buffered | buffer create 29 B |
| 40x2 | confidential signer | message bytes | 7587 | 10206 | 10162 | 2403 | 64 | 3 | 3 | buffered | buffer create 1 B |
| 40x2 | confidential in-proof | messages | 221 | 10195 | 10152 | 2306 | 63 | 2 | 3 | buffered | buffer create 23 B |
| 40x2 | confidential in-proof | message bytes | 7491 | 10206 | 10163 | 2306 | 63 | 2 | 3 | buffered | buffer create 1 B |
| 40x2 | anonymous hidden | reply | 7380 | 10206 | 10202 | 2210 | 60 | 2 | 3 | buffered | buffer create 1 B |
| 40x2 | anonymous hidden | messages | 214 | 10200 | 10195 | 2210 | 60 | 2 | 3 | buffered | buffer create 28 B |
| 40x2 | anonymous hidden | message bytes | 7248 | 10206 | 10201 | 2210 | 60 | 2 | 3 | buffered | buffer create 1 B |
| 40x2 | anonymous public owners | reply | 7444 | 10206 | 10169 | 2403 | 64 | 3 | 3 | buffered | buffer create 1 B |
| 40x2 | anonymous public owners | messages | 216 | 10204 | 10166 | 2403 | 64 | 3 | 3 | buffered | buffer create 32 B |
| 40x2 | anonymous public owners | message bytes | 7312 | 10206 | 10168 | 2403 | 64 | 3 | 3 | buffered | buffer create 1 B |
| 48x2 | confidential signer | messages | none | - | - | - | - | - | - | no | 8 accounts |
| 48x2 | confidential signer | message bytes | none | - | - | - | - | - | - | no | 8 accounts |
| 48x2 | confidential in-proof | messages | none | - | - | - | - | - | - | no | 7 accounts |
| 48x2 | confidential in-proof | message bytes | none | - | - | - | - | - | - | no | 7 accounts |
| 48x2 | anonymous hidden | reply | none | - | - | - | - | - | - | no | 4 accounts |
| 48x2 | anonymous hidden | messages | none | - | - | - | - | - | - | no | 4 accounts |
| 48x2 | anonymous hidden | message bytes | none | - | - | - | - | - | - | no | 4 accounts |
| 48x2 | anonymous public owners | reply | none | - | - | - | - | - | - | no | 8 accounts |
| 48x2 | anonymous public owners | messages | none | - | - | - | - | - | - | no | 8 accounts |
| 48x2 | anonymous public owners | message bytes | none | - | - | - | - | - | - | no | 8 accounts |
| 49x2 | confidential signer | messages | none | - | - | - | - | - | - | no | 9 accounts |
| 49x2 | confidential signer | message bytes | none | - | - | - | - | - | - | no | 9 accounts |
| 49x2 | confidential in-proof | messages | none | - | - | - | - | - | - | no | 8 accounts |
| 49x2 | confidential in-proof | message bytes | none | - | - | - | - | - | - | no | 8 accounts |
| 49x2 | anonymous hidden | reply | none | - | - | - | - | - | - | no | 5 accounts |
| 49x2 | anonymous hidden | messages | none | - | - | - | - | - | - | no | 5 accounts |
| 49x2 | anonymous hidden | message bytes | none | - | - | - | - | - | - | no | 5 accounts |
| 49x2 | anonymous public owners | reply | none | - | - | - | - | - | - | no | 9 accounts |
| 49x2 | anonymous public owners | messages | none | - | - | - | - | - | - | no | 9 accounts |
| 49x2 | anonymous public owners | message bytes | none | - | - | - | - | - | - | no | 9 accounts |
