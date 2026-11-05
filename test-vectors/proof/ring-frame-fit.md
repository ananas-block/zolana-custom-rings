Measured with the frame encoders, SPP's account builders and the v1 compiler. Ceilings 4096 B, 64 accounts, 12 signatures.
min: one credential state tree, no co-signer, no leg, no fee, the payer an owner where it may be. full: own and curator roots, two credential state trees, one co-signer, 4 SOL legs, a fee, an outside payer, a body on every slot and one exit. Shared loads start credential state trees at tree zero and reuse the first SPP input tree as the address tree. Both full+4credential loads carry four credential state trees and two SPP input trees. The disjoint load uses separate address, credential state and SPP input trees. Full deposits use one credential state tree per slot. Ring-authority merges read one credential state tree. Owner-signed merges read none. The owner run is the ceilings' bound under full, the key's rows bound it apart. A shape's every input and output slot is published.
Every row is one transaction. fits: the row clears the transaction and CPI ceilings and the selected key credential capacity. limit: what refuses a row, rail for a shape the rail has no SPP key for, else the excess in credential trees, accounts, signatures, bytes or CPI data at that row's load. A missing catalog key has no encoded measurement.
| shape | rail | load | catalog key | bytes | accounts | signatures | owner run | frame | SPP CPI | fits | limit |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1x2 | confidential signer | min | yes | 1314 | 8 | 1 | - | 929 | 945 | yes |  |
| 1x2 | confidential signer | full | yes | 1904 | 19 | 3 | 1 | 1018 | 990 | yes |  |
| 1x2 | confidential signer | full+spl | yes | 2272 | 26 | 3 | - | 1150 | 994 | yes |  |
| 1x2 | confidential signer | full+data | yes | 2104 | 19 | 3 | - | 1218 | 1186 | yes |  |
| 1x2 | confidential signer | full+reply | yes | 1904 | 19 | 3 | - | 1018 | 990 | yes |  |
| 1x2 | confidential signer | full+2tree | yes | 1910 | 19 | 3 | - | 1023 | 994 | yes |  |
| 1x2 | confidential signer | full+4credential-shared | yes | 1980 | 21 | 3 | - | 1027 | 994 | yes |  |
| 1x2 | confidential signer | full+4credential-disjoint | yes | 2076 | 24 | 3 | - | 1027 | 994 | yes |  |
| 1x2 | confidential in-proof | min | yes | 1409 | 8 | 1 | - | 1025 | 1042 | yes |  |
| 1x2 | confidential in-proof | full | yes | 1903 | 18 | 2 | 1 | 1114 | 1087 | yes |  |
| 1x2 | confidential in-proof | full+spl | yes | 2271 | 25 | 2 | - | 1246 | 1091 | yes |  |
| 1x2 | confidential in-proof | full+data | yes | 2103 | 18 | 2 | - | 1314 | 1283 | yes |  |
| 1x2 | confidential in-proof | full+reply | yes | 1903 | 18 | 2 | - | 1114 | 1087 | yes |  |
| 1x2 | confidential in-proof | full+2tree | yes | 1909 | 18 | 2 | - | 1119 | 1091 | yes |  |
| 1x2 | confidential in-proof | full+4credential-shared | yes | 1979 | 20 | 2 | - | 1123 | 1091 | yes |  |
| 1x2 | confidential in-proof | full+4credential-disjoint | yes | 2075 | 23 | 2 | - | 1123 | 1091 | yes |  |
| 1x2 | anonymous hidden | min | yes | 1481 | 8 | 1 | - | 1097 | 1144 | yes |  |
| 1x2 | anonymous hidden | full | yes | 1951 | 15 | 2 | 1 | 1258 | 1271 | yes |  |
| 1x2 | anonymous hidden | full+spl | yes | 2319 | 22 | 2 | - | 1390 | 1275 | yes |  |
| 1x2 | anonymous hidden | full+data | yes | 2151 | 15 | 2 | - | 1458 | 1467 | yes |  |
| 1x2 | anonymous hidden | full+reply | yes | 2050 | 15 | 2 | - | 1357 | 1368 | yes |  |
| 1x2 | anonymous hidden | full+2tree | yes | 1957 | 15 | 2 | - | 1263 | 1275 | yes |  |
| 1x2 | anonymous hidden | full+4credential-shared | yes | 2027 | 17 | 2 | - | 1267 | 1275 | yes |  |
| 1x2 | anonymous hidden | full+4credential-disjoint | yes | 2123 | 20 | 2 | - | 1267 | 1275 | yes |  |
| 1x2 | anonymous public owners | min | yes | 1418 | 8 | 1 | - | 1033 | 1047 | yes |  |
| 1x2 | anonymous public owners | full | yes | 2080 | 19 | 3 | 1 | 1194 | 1174 | yes |  |
| 1x2 | anonymous public owners | full+spl | yes | 2448 | 26 | 3 | - | 1326 | 1178 | yes |  |
| 1x2 | anonymous public owners | full+data | yes | 2280 | 19 | 3 | - | 1394 | 1370 | yes |  |
| 1x2 | anonymous public owners | full+reply | yes | 2179 | 19 | 3 | - | 1293 | 1271 | yes |  |
| 1x2 | anonymous public owners | full+2tree | yes | 2086 | 19 | 3 | - | 1199 | 1178 | yes |  |
| 1x2 | anonymous public owners | full+4credential-shared | yes | 2156 | 21 | 3 | - | 1203 | 1178 | yes |  |
| 1x2 | anonymous public owners | full+4credential-disjoint | yes | 2252 | 24 | 3 | - | 1203 | 1178 | yes |  |
| 1x2 | confidential entry | min | yes | 1522 | 8 | 1 | - | 1137 | 1153 | yes |  |
| 1x2 | confidential entry | full | yes | 2112 | 19 | 3 | 1 | 1226 | 1198 | yes |  |
| 1x2 | confidential entry | full+spl | yes | 2480 | 26 | 3 | - | 1358 | 1202 | yes |  |
| 1x2 | confidential entry | full+data | yes | 2312 | 19 | 3 | - | 1426 | 1394 | yes |  |
| 1x2 | confidential entry | full+reply | yes | 2112 | 19 | 3 | - | 1226 | 1198 | yes |  |
| 1x2 | confidential entry | full+2tree | yes | 2118 | 19 | 3 | - | 1231 | 1202 | yes |  |
| 1x2 | confidential entry | full+4credential-shared | yes | 2188 | 21 | 3 | - | 1235 | 1202 | yes |  |
| 1x2 | confidential entry | full+4credential-disjoint | yes | 2284 | 24 | 3 | - | 1235 | 1202 | yes |  |
| 1x2 | anonymous entry | min | yes | 1721 | 8 | 1 | - | 1337 | 1352 | yes |  |
| 1x2 | anonymous entry | full | yes | 2191 | 15 | 2 | 1 | 1498 | 1479 | yes |  |
| 1x2 | anonymous entry | full+spl | yes | 2559 | 22 | 2 | - | 1630 | 1483 | yes |  |
| 1x2 | anonymous entry | full+data | yes | 2391 | 15 | 2 | - | 1698 | 1675 | yes |  |
| 1x2 | anonymous entry | full+reply | yes | 2290 | 15 | 2 | - | 1597 | 1576 | yes |  |
| 1x2 | anonymous entry | full+2tree | yes | 2197 | 15 | 2 | - | 1503 | 1483 | yes |  |
| 1x2 | anonymous entry | full+4credential-shared | yes | 2267 | 17 | 2 | - | 1507 | 1483 | yes |  |
| 1x2 | anonymous entry | full+4credential-disjoint | yes | 2363 | 20 | 2 | - | 1507 | 1483 | yes |  |
| 1x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x4 | confidential signer | min | yes | 1748 | 8 | 1 | - | 1363 | 1451 | yes |  |
| 1x4 | confidential signer | full | yes | 2338 | 19 | 3 | 1 | 1452 | 1496 | yes |  |
| 1x4 | confidential signer | full+spl | yes | 2706 | 26 | 3 | - | 1584 | 1500 | yes |  |
| 1x4 | confidential signer | full+data | yes | 2736 | 19 | 3 | - | 1850 | 1886 | yes |  |
| 1x4 | confidential signer | full+reply | yes | 2338 | 19 | 3 | - | 1452 | 1496 | yes |  |
| 1x4 | confidential signer | full+2tree | yes | 2344 | 19 | 3 | - | 1457 | 1500 | yes |  |
| 1x4 | confidential signer | full+4credential-shared | yes | 2414 | 21 | 3 | - | 1461 | 1500 | yes |  |
| 1x4 | confidential signer | full+4credential-disjoint | yes | 2510 | 24 | 3 | - | 1461 | 1500 | yes |  |
| 1x4 | confidential in-proof | min | yes | 1843 | 8 | 1 | - | 1459 | 1548 | yes |  |
| 1x4 | confidential in-proof | full | yes | 2337 | 18 | 2 | 1 | 1548 | 1593 | yes |  |
| 1x4 | confidential in-proof | full+spl | yes | 2705 | 25 | 2 | - | 1680 | 1597 | yes |  |
| 1x4 | confidential in-proof | full+data | yes | 2735 | 18 | 2 | - | 1946 | 1983 | yes |  |
| 1x4 | confidential in-proof | full+reply | yes | 2337 | 18 | 2 | - | 1548 | 1593 | yes |  |
| 1x4 | confidential in-proof | full+2tree | yes | 2343 | 18 | 2 | - | 1553 | 1597 | yes |  |
| 1x4 | confidential in-proof | full+4credential-shared | yes | 2413 | 20 | 2 | - | 1557 | 1597 | yes |  |
| 1x4 | confidential in-proof | full+4credential-disjoint | yes | 2509 | 23 | 2 | - | 1557 | 1597 | yes |  |
| 1x4 | anonymous hidden | min | yes | 1979 | 8 | 1 | - | 1595 | 1714 | yes |  |
| 1x4 | anonymous hidden | full | yes | 2449 | 15 | 2 | 1 | 1756 | 1841 | yes |  |
| 1x4 | anonymous hidden | full+spl | yes | 2817 | 22 | 2 | - | 1888 | 1845 | yes |  |
| 1x4 | anonymous hidden | full+data | yes | 2847 | 15 | 2 | - | 2154 | 2231 | yes |  |
| 1x4 | anonymous hidden | full+reply | yes | 2742 | 15 | 2 | - | 2049 | 2132 | yes |  |
| 1x4 | anonymous hidden | full+2tree | yes | 2455 | 15 | 2 | - | 1761 | 1845 | yes |  |
| 1x4 | anonymous hidden | full+4credential-shared | yes | 2525 | 17 | 2 | - | 1765 | 1845 | yes |  |
| 1x4 | anonymous hidden | full+4credential-disjoint | yes | 2621 | 20 | 2 | - | 1765 | 1845 | yes |  |
| 1x4 | anonymous public owners | min | yes | 1916 | 8 | 1 | - | 1531 | 1617 | yes |  |
| 1x4 | anonymous public owners | full | yes | 2578 | 19 | 3 | 1 | 1692 | 1744 | yes |  |
| 1x4 | anonymous public owners | full+spl | yes | 2946 | 26 | 3 | - | 1824 | 1748 | yes |  |
| 1x4 | anonymous public owners | full+data | yes | 2976 | 19 | 3 | - | 2090 | 2134 | yes |  |
| 1x4 | anonymous public owners | full+reply | yes | 2871 | 19 | 3 | - | 1985 | 2035 | yes |  |
| 1x4 | anonymous public owners | full+2tree | yes | 2584 | 19 | 3 | - | 1697 | 1748 | yes |  |
| 1x4 | anonymous public owners | full+4credential-shared | yes | 2654 | 21 | 3 | - | 1701 | 1748 | yes |  |
| 1x4 | anonymous public owners | full+4credential-disjoint | yes | 2750 | 24 | 3 | - | 1701 | 1748 | yes |  |
| 1x4 | confidential entry | min | yes | 1956 | 8 | 1 | - | 1571 | 1659 | yes |  |
| 1x4 | confidential entry | full | yes | 2546 | 19 | 3 | 1 | 1660 | 1704 | yes |  |
| 1x4 | confidential entry | full+spl | yes | 2914 | 26 | 3 | - | 1792 | 1708 | yes |  |
| 1x4 | confidential entry | full+data | yes | 2944 | 19 | 3 | - | 2058 | 2094 | yes |  |
| 1x4 | confidential entry | full+reply | yes | 2546 | 19 | 3 | - | 1660 | 1704 | yes |  |
| 1x4 | confidential entry | full+2tree | yes | 2552 | 19 | 3 | - | 1665 | 1708 | yes |  |
| 1x4 | confidential entry | full+4credential-shared | yes | 2622 | 21 | 3 | - | 1669 | 1708 | yes |  |
| 1x4 | confidential entry | full+4credential-disjoint | yes | 2718 | 24 | 3 | - | 1669 | 1708 | yes |  |
| 1x4 | anonymous entry | min | yes | 2219 | 8 | 1 | - | 1835 | 1922 | yes |  |
| 1x4 | anonymous entry | full | yes | 2689 | 15 | 2 | 1 | 1996 | 2049 | yes |  |
| 1x4 | anonymous entry | full+spl | yes | 3057 | 22 | 2 | - | 2128 | 2053 | yes |  |
| 1x4 | anonymous entry | full+data | yes | 3087 | 15 | 2 | - | 2394 | 2439 | yes |  |
| 1x4 | anonymous entry | full+reply | yes | 2982 | 15 | 2 | - | 2289 | 2340 | yes |  |
| 1x4 | anonymous entry | full+2tree | yes | 2695 | 15 | 2 | - | 2001 | 2053 | yes |  |
| 1x4 | anonymous entry | full+4credential-shared | yes | 2765 | 17 | 2 | - | 2005 | 2053 | yes |  |
| 1x4 | anonymous entry | full+4credential-disjoint | yes | 2861 | 20 | 2 | - | 2005 | 2053 | yes |  |
| 1x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x8 | confidential signer | min | yes | 2616 | 8 | 1 | - | 2231 | 2463 | yes |  |
| 1x8 | confidential signer | full | yes | 3206 | 19 | 3 | 1 | 2320 | 2508 | yes |  |
| 1x8 | confidential signer | full+spl | yes | 3574 | 26 | 3 | - | 2452 | 2512 | yes |  |
| 1x8 | confidential signer | full+data | yes | 4000 | 19 | 3 | - | 3114 | 3286 | yes |  |
| 1x8 | confidential signer | full+reply | yes | 3206 | 19 | 3 | - | 2320 | 2508 | yes |  |
| 1x8 | confidential signer | full+2tree | yes | 3212 | 19 | 3 | - | 2325 | 2512 | yes |  |
| 1x8 | confidential signer | full+4credential-shared | yes | 3282 | 21 | 3 | - | 2329 | 2512 | yes |  |
| 1x8 | confidential signer | full+4credential-disjoint | yes | 3378 | 24 | 3 | - | 2329 | 2512 | yes |  |
| 1x8 | confidential in-proof | min | yes | 2711 | 8 | 1 | - | 2327 | 2560 | yes |  |
| 1x8 | confidential in-proof | full | yes | 3205 | 18 | 2 | 1 | 2416 | 2605 | yes |  |
| 1x8 | confidential in-proof | full+spl | yes | 3573 | 25 | 2 | - | 2548 | 2609 | yes |  |
| 1x8 | confidential in-proof | full+data | yes | 3999 | 18 | 2 | - | 3210 | 3383 | yes |  |
| 1x8 | confidential in-proof | full+reply | yes | 3205 | 18 | 2 | - | 2416 | 2605 | yes |  |
| 1x8 | confidential in-proof | full+2tree | yes | 3211 | 18 | 2 | - | 2421 | 2609 | yes |  |
| 1x8 | confidential in-proof | full+4credential-shared | yes | 3281 | 20 | 2 | - | 2425 | 2609 | yes |  |
| 1x8 | confidential in-proof | full+4credential-disjoint | yes | 3377 | 23 | 2 | - | 2425 | 2609 | yes |  |
| 1x8 | anonymous hidden | min | yes | 2975 | 8 | 1 | - | 2591 | 2854 | yes |  |
| 1x8 | anonymous hidden | full | yes | 3445 | 15 | 2 | 1 | 2752 | 2981 | yes |  |
| 1x8 | anonymous hidden | full+spl | yes | 3813 | 22 | 2 | - | 2884 | 2985 | yes |  |
| 1x8 | anonymous hidden | full+data | yes | 4239 | 15 | 2 | - | 3546 | 3759 | no | 143 B |
| 1x8 | anonymous hidden | full+reply | yes | 4126 | 15 | 2 | - | 3433 | 3660 | no | 30 B |
| 1x8 | anonymous hidden | full+2tree | yes | 3451 | 15 | 2 | - | 2757 | 2985 | yes |  |
| 1x8 | anonymous hidden | full+4credential-shared | yes | 3521 | 17 | 2 | - | 2761 | 2985 | yes |  |
| 1x8 | anonymous hidden | full+4credential-disjoint | yes | 3617 | 20 | 2 | - | 2761 | 2985 | yes |  |
| 1x8 | anonymous public owners | min | yes | 2912 | 8 | 1 | - | 2527 | 2757 | yes |  |
| 1x8 | anonymous public owners | full | yes | 3574 | 19 | 3 | 1 | 2688 | 2884 | yes |  |
| 1x8 | anonymous public owners | full+spl | yes | 3942 | 26 | 3 | - | 2820 | 2888 | yes |  |
| 1x8 | anonymous public owners | full+data | yes | 4368 | 19 | 3 | - | 3482 | 3662 | no | 272 B |
| 1x8 | anonymous public owners | full+reply | yes | 4255 | 19 | 3 | - | 3369 | 3563 | no | 159 B |
| 1x8 | anonymous public owners | full+2tree | yes | 3580 | 19 | 3 | - | 2693 | 2888 | yes |  |
| 1x8 | anonymous public owners | full+4credential-shared | yes | 3650 | 21 | 3 | - | 2697 | 2888 | yes |  |
| 1x8 | anonymous public owners | full+4credential-disjoint | yes | 3746 | 24 | 3 | - | 2697 | 2888 | yes |  |
| 1x8 | confidential entry | min | yes | 2824 | 8 | 1 | - | 2439 | 2671 | yes |  |
| 1x8 | confidential entry | full | yes | 3414 | 19 | 3 | 1 | 2528 | 2716 | yes |  |
| 1x8 | confidential entry | full+spl | yes | 3782 | 26 | 3 | - | 2660 | 2720 | yes |  |
| 1x8 | confidential entry | full+data | yes | 4208 | 19 | 3 | - | 3322 | 3494 | no | 112 B |
| 1x8 | confidential entry | full+reply | yes | 3414 | 19 | 3 | - | 2528 | 2716 | yes |  |
| 1x8 | confidential entry | full+2tree | yes | 3420 | 19 | 3 | - | 2533 | 2720 | yes |  |
| 1x8 | confidential entry | full+4credential-shared | yes | 3490 | 21 | 3 | - | 2537 | 2720 | yes |  |
| 1x8 | confidential entry | full+4credential-disjoint | yes | 3586 | 24 | 3 | - | 2537 | 2720 | yes |  |
| 1x8 | anonymous entry | min | yes | 3215 | 8 | 1 | - | 2831 | 3062 | yes |  |
| 1x8 | anonymous entry | full | yes | 3685 | 15 | 2 | 1 | 2992 | 3189 | yes |  |
| 1x8 | anonymous entry | full+spl | yes | 4053 | 22 | 2 | - | 3124 | 3193 | yes |  |
| 1x8 | anonymous entry | full+data | yes | 4479 | 15 | 2 | - | 3786 | 3967 | no | 383 B |
| 1x8 | anonymous entry | full+reply | yes | 4366 | 15 | 2 | - | 3673 | 3868 | no | 270 B |
| 1x8 | anonymous entry | full+2tree | yes | 3691 | 15 | 2 | - | 2997 | 3193 | yes |  |
| 1x8 | anonymous entry | full+4credential-shared | yes | 3761 | 17 | 2 | - | 3001 | 3193 | yes |  |
| 1x8 | anonymous entry | full+4credential-disjoint | yes | 3857 | 20 | 2 | - | 3001 | 3193 | yes |  |
| 1x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x2 | confidential signer | min | yes | 1379 | 9 | 1 | - | 961 | 978 | yes |  |
| 2x2 | confidential signer | full | yes | 1969 | 20 | 3 | 2 | 1050 | 1023 | yes |  |
| 2x2 | confidential signer | full+spl | yes | 2337 | 27 | 3 | - | 1182 | 1027 | yes |  |
| 2x2 | confidential signer | full+data | yes | 2169 | 20 | 3 | - | 1250 | 1219 | yes |  |
| 2x2 | confidential signer | full+reply | yes | 1969 | 20 | 3 | - | 1050 | 1023 | yes |  |
| 2x2 | confidential signer | full+2tree | yes | 1975 | 20 | 3 | - | 1055 | 1027 | yes |  |
| 2x2 | confidential signer | full+4credential-shared | yes | 2045 | 22 | 3 | - | 1059 | 1027 | yes |  |
| 2x2 | confidential signer | full+4credential-disjoint | yes | 2141 | 25 | 3 | - | 1059 | 1027 | yes |  |
| 2x2 | confidential in-proof | min | yes | 1474 | 9 | 1 | - | 1057 | 1075 | yes |  |
| 2x2 | confidential in-proof | full | yes | 1968 | 19 | 2 | 2 | 1146 | 1120 | yes |  |
| 2x2 | confidential in-proof | full+spl | yes | 2336 | 26 | 2 | - | 1278 | 1124 | yes |  |
| 2x2 | confidential in-proof | full+data | yes | 2168 | 19 | 2 | - | 1346 | 1316 | yes |  |
| 2x2 | confidential in-proof | full+reply | yes | 1968 | 19 | 2 | - | 1146 | 1120 | yes |  |
| 2x2 | confidential in-proof | full+2tree | yes | 1974 | 19 | 2 | - | 1151 | 1124 | yes |  |
| 2x2 | confidential in-proof | full+4credential-shared | yes | 2044 | 21 | 2 | - | 1155 | 1124 | yes |  |
| 2x2 | confidential in-proof | full+4credential-disjoint | yes | 2140 | 24 | 2 | - | 1155 | 1124 | yes |  |
| 2x2 | anonymous hidden | min | yes | 1546 | 9 | 1 | - | 1129 | 1177 | yes |  |
| 2x2 | anonymous hidden | full | yes | 2016 | 16 | 2 | 2 | 1290 | 1304 | yes |  |
| 2x2 | anonymous hidden | full+spl | yes | 2384 | 23 | 2 | - | 1422 | 1308 | yes |  |
| 2x2 | anonymous hidden | full+data | yes | 2216 | 16 | 2 | - | 1490 | 1500 | yes |  |
| 2x2 | anonymous hidden | full+reply | yes | 2115 | 16 | 2 | - | 1389 | 1401 | yes |  |
| 2x2 | anonymous hidden | full+2tree | yes | 2022 | 16 | 2 | - | 1295 | 1308 | yes |  |
| 2x2 | anonymous hidden | full+4credential-shared | yes | 2092 | 18 | 2 | - | 1299 | 1308 | yes |  |
| 2x2 | anonymous hidden | full+4credential-disjoint | yes | 2188 | 21 | 2 | - | 1299 | 1308 | yes |  |
| 2x2 | anonymous public owners | min | yes | 1483 | 9 | 1 | - | 1065 | 1080 | yes |  |
| 2x2 | anonymous public owners | full | yes | 2145 | 20 | 3 | 2 | 1226 | 1207 | yes |  |
| 2x2 | anonymous public owners | full+spl | yes | 2513 | 27 | 3 | - | 1358 | 1211 | yes |  |
| 2x2 | anonymous public owners | full+data | yes | 2345 | 20 | 3 | - | 1426 | 1403 | yes |  |
| 2x2 | anonymous public owners | full+reply | yes | 2244 | 20 | 3 | - | 1325 | 1304 | yes |  |
| 2x2 | anonymous public owners | full+2tree | yes | 2151 | 20 | 3 | - | 1231 | 1211 | yes |  |
| 2x2 | anonymous public owners | full+4credential-shared | yes | 2221 | 22 | 3 | - | 1235 | 1211 | yes |  |
| 2x2 | anonymous public owners | full+4credential-disjoint | yes | 2317 | 25 | 3 | - | 1235 | 1211 | yes |  |
| 2x2 | confidential entry | min | yes | 1787 | 9 | 1 | - | 1369 | 1386 | yes |  |
| 2x2 | confidential entry | full | yes | 2377 | 20 | 3 | 2 | 1458 | 1431 | yes |  |
| 2x2 | confidential entry | full+spl | yes | 2745 | 27 | 3 | - | 1590 | 1435 | yes |  |
| 2x2 | confidential entry | full+data | yes | 2577 | 20 | 3 | - | 1658 | 1627 | yes |  |
| 2x2 | confidential entry | full+reply | yes | 2377 | 20 | 3 | - | 1458 | 1431 | yes |  |
| 2x2 | confidential entry | full+2tree | yes | 2383 | 20 | 3 | - | 1463 | 1435 | yes |  |
| 2x2 | confidential entry | full+4credential-shared | yes | 2453 | 22 | 3 | - | 1467 | 1435 | yes |  |
| 2x2 | confidential entry | full+4credential-disjoint | yes | 2549 | 25 | 3 | - | 1467 | 1435 | yes |  |
| 2x2 | anonymous entry | min | yes | 1986 | 9 | 1 | - | 1569 | 1585 | yes |  |
| 2x2 | anonymous entry | full | yes | 2456 | 16 | 2 | 2 | 1730 | 1712 | yes |  |
| 2x2 | anonymous entry | full+spl | yes | 2824 | 23 | 2 | - | 1862 | 1716 | yes |  |
| 2x2 | anonymous entry | full+data | yes | 2656 | 16 | 2 | - | 1930 | 1908 | yes |  |
| 2x2 | anonymous entry | full+reply | yes | 2555 | 16 | 2 | - | 1829 | 1809 | yes |  |
| 2x2 | anonymous entry | full+2tree | yes | 2462 | 16 | 2 | - | 1735 | 1716 | yes |  |
| 2x2 | anonymous entry | full+4credential-shared | yes | 2532 | 18 | 2 | - | 1739 | 1716 | yes |  |
| 2x2 | anonymous entry | full+4credential-disjoint | yes | 2628 | 21 | 2 | - | 1739 | 1716 | yes |  |
| 2x2 | delegate | min | yes | 1379 | 9 | 1 | - | 961 | 978 | yes |  |
| 2x2 | delegate | full | yes | 1757 | 16 | 2 | - | 1034 | 1023 | yes |  |
| 2x2 | delegate | full+spl | yes | 1997 | 23 | 2 | - | 1038 | 1027 | yes |  |
| 2x2 | delegate | full+data | yes | 1957 | 16 | 2 | - | 1234 | 1219 | yes |  |
| 2x2 | delegate | full+reply | yes | 1757 | 16 | 2 | - | 1034 | 1023 | yes |  |
| 2x2 | delegate | full+2tree | yes | 1763 | 16 | 2 | - | 1039 | 1027 | yes |  |
| 2x2 | delegate | full+4credential-shared | yes | 1833 | 18 | 2 | - | 1043 | 1027 | yes |  |
| 2x2 | delegate | full+4credential-disjoint | yes | 1929 | 21 | 2 | - | 1043 | 1027 | yes |  |
| 2x2 | anonymous delegate | min | yes | 1483 | 9 | 1 | - | 1065 | 1080 | yes |  |
| 2x2 | anonymous delegate | full | yes | 1933 | 16 | 2 | - | 1210 | 1207 | yes |  |
| 2x2 | anonymous delegate | full+spl | yes | 2173 | 23 | 2 | - | 1214 | 1211 | yes |  |
| 2x2 | anonymous delegate | full+data | yes | 2133 | 16 | 2 | - | 1410 | 1403 | yes |  |
| 2x2 | anonymous delegate | full+reply | yes | 2032 | 16 | 2 | - | 1309 | 1304 | yes |  |
| 2x2 | anonymous delegate | full+2tree | yes | 1939 | 16 | 2 | - | 1215 | 1211 | yes |  |
| 2x2 | anonymous delegate | full+4credential-shared | yes | 2009 | 18 | 2 | - | 1219 | 1211 | yes |  |
| 2x2 | anonymous delegate | full+4credential-disjoint | yes | 2105 | 21 | 2 | - | 1219 | 1211 | yes |  |
| 2x4 | confidential signer | min | yes | 1813 | 9 | 1 | - | 1395 | 1484 | yes |  |
| 2x4 | confidential signer | full | yes | 2403 | 20 | 3 | 2 | 1484 | 1529 | yes |  |
| 2x4 | confidential signer | full+spl | yes | 2771 | 27 | 3 | - | 1616 | 1533 | yes |  |
| 2x4 | confidential signer | full+data | yes | 2801 | 20 | 3 | - | 1882 | 1919 | yes |  |
| 2x4 | confidential signer | full+reply | yes | 2403 | 20 | 3 | - | 1484 | 1529 | yes |  |
| 2x4 | confidential signer | full+2tree | yes | 2409 | 20 | 3 | - | 1489 | 1533 | yes |  |
| 2x4 | confidential signer | full+4credential-shared | yes | 2479 | 22 | 3 | - | 1493 | 1533 | yes |  |
| 2x4 | confidential signer | full+4credential-disjoint | yes | 2575 | 25 | 3 | - | 1493 | 1533 | yes |  |
| 2x4 | confidential in-proof | min | yes | 1908 | 9 | 1 | - | 1491 | 1581 | yes |  |
| 2x4 | confidential in-proof | full | yes | 2402 | 19 | 2 | 2 | 1580 | 1626 | yes |  |
| 2x4 | confidential in-proof | full+spl | yes | 2770 | 26 | 2 | - | 1712 | 1630 | yes |  |
| 2x4 | confidential in-proof | full+data | yes | 2800 | 19 | 2 | - | 1978 | 2016 | yes |  |
| 2x4 | confidential in-proof | full+reply | yes | 2402 | 19 | 2 | - | 1580 | 1626 | yes |  |
| 2x4 | confidential in-proof | full+2tree | yes | 2408 | 19 | 2 | - | 1585 | 1630 | yes |  |
| 2x4 | confidential in-proof | full+4credential-shared | yes | 2478 | 21 | 2 | - | 1589 | 1630 | yes |  |
| 2x4 | confidential in-proof | full+4credential-disjoint | yes | 2574 | 24 | 2 | - | 1589 | 1630 | yes |  |
| 2x4 | anonymous hidden | min | yes | 2044 | 9 | 1 | - | 1627 | 1747 | yes |  |
| 2x4 | anonymous hidden | full | yes | 2514 | 16 | 2 | 2 | 1788 | 1874 | yes |  |
| 2x4 | anonymous hidden | full+spl | yes | 2882 | 23 | 2 | - | 1920 | 1878 | yes |  |
| 2x4 | anonymous hidden | full+data | yes | 2912 | 16 | 2 | - | 2186 | 2264 | yes |  |
| 2x4 | anonymous hidden | full+reply | yes | 2807 | 16 | 2 | - | 2081 | 2165 | yes |  |
| 2x4 | anonymous hidden | full+2tree | yes | 2520 | 16 | 2 | - | 1793 | 1878 | yes |  |
| 2x4 | anonymous hidden | full+4credential-shared | yes | 2590 | 18 | 2 | - | 1797 | 1878 | yes |  |
| 2x4 | anonymous hidden | full+4credential-disjoint | yes | 2686 | 21 | 2 | - | 1797 | 1878 | yes |  |
| 2x4 | anonymous public owners | min | yes | 1981 | 9 | 1 | - | 1563 | 1650 | yes |  |
| 2x4 | anonymous public owners | full | yes | 2643 | 20 | 3 | 2 | 1724 | 1777 | yes |  |
| 2x4 | anonymous public owners | full+spl | yes | 3011 | 27 | 3 | - | 1856 | 1781 | yes |  |
| 2x4 | anonymous public owners | full+data | yes | 3041 | 20 | 3 | - | 2122 | 2167 | yes |  |
| 2x4 | anonymous public owners | full+reply | yes | 2936 | 20 | 3 | - | 2017 | 2068 | yes |  |
| 2x4 | anonymous public owners | full+2tree | yes | 2649 | 20 | 3 | - | 1729 | 1781 | yes |  |
| 2x4 | anonymous public owners | full+4credential-shared | yes | 2719 | 22 | 3 | - | 1733 | 1781 | yes |  |
| 2x4 | anonymous public owners | full+4credential-disjoint | yes | 2815 | 25 | 3 | - | 1733 | 1781 | yes |  |
| 2x4 | confidential entry | min | yes | 2221 | 9 | 1 | - | 1803 | 1892 | yes |  |
| 2x4 | confidential entry | full | yes | 2811 | 20 | 3 | 2 | 1892 | 1937 | yes |  |
| 2x4 | confidential entry | full+spl | yes | 3179 | 27 | 3 | - | 2024 | 1941 | yes |  |
| 2x4 | confidential entry | full+data | yes | 3209 | 20 | 3 | - | 2290 | 2327 | yes |  |
| 2x4 | confidential entry | full+reply | yes | 2811 | 20 | 3 | - | 1892 | 1937 | yes |  |
| 2x4 | confidential entry | full+2tree | yes | 2817 | 20 | 3 | - | 1897 | 1941 | yes |  |
| 2x4 | confidential entry | full+4credential-shared | yes | 2887 | 22 | 3 | - | 1901 | 1941 | yes |  |
| 2x4 | confidential entry | full+4credential-disjoint | yes | 2983 | 25 | 3 | - | 1901 | 1941 | yes |  |
| 2x4 | anonymous entry | min | yes | 2484 | 9 | 1 | - | 2067 | 2155 | yes |  |
| 2x4 | anonymous entry | full | yes | 2954 | 16 | 2 | 2 | 2228 | 2282 | yes |  |
| 2x4 | anonymous entry | full+spl | yes | 3322 | 23 | 2 | - | 2360 | 2286 | yes |  |
| 2x4 | anonymous entry | full+data | yes | 3352 | 16 | 2 | - | 2626 | 2672 | yes |  |
| 2x4 | anonymous entry | full+reply | yes | 3247 | 16 | 2 | - | 2521 | 2573 | yes |  |
| 2x4 | anonymous entry | full+2tree | yes | 2960 | 16 | 2 | - | 2233 | 2286 | yes |  |
| 2x4 | anonymous entry | full+4credential-shared | yes | 3030 | 18 | 2 | - | 2237 | 2286 | yes |  |
| 2x4 | anonymous entry | full+4credential-disjoint | yes | 3126 | 21 | 2 | - | 2237 | 2286 | yes |  |
| 2x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x16 | confidential signer | min | yes | 4354 | 8 | 1 | - | 3969 | 4487 | no | 258 B |
| 1x16 | confidential signer | full | yes | 4944 | 19 | 3 | none | 4058 | 4532 | no | 848 B |
| 1x16 | confidential signer | full+spl | yes | 5312 | 26 | 3 | - | 4190 | 4536 | no | 1216 B |
| 1x16 | confidential signer | full+data | yes | 6530 | 19 | 3 | - | 5644 | 6086 | no | 2434 B |
| 1x16 | confidential signer | full+reply | yes | 4944 | 19 | 3 | - | 4058 | 4532 | no | 848 B |
| 1x16 | confidential signer | full+2tree | yes | 4950 | 19 | 3 | - | 4063 | 4536 | no | 854 B |
| 1x16 | confidential signer | full+4credential-shared | yes | 5020 | 21 | 3 | - | 4067 | 4536 | no | 924 B |
| 1x16 | confidential signer | full+4credential-disjoint | yes | 5116 | 24 | 3 | - | 4067 | 4536 | no | 1020 B |
| 1x16 | confidential in-proof | min | yes | 4449 | 8 | 1 | - | 4065 | 4584 | no | 353 B |
| 1x16 | confidential in-proof | full | yes | 4943 | 18 | 2 | none | 4154 | 4629 | no | 847 B |
| 1x16 | confidential in-proof | full+spl | yes | 5311 | 25 | 2 | - | 4286 | 4633 | no | 1215 B |
| 1x16 | confidential in-proof | full+data | yes | 6529 | 18 | 2 | - | 5740 | 6183 | no | 2433 B |
| 1x16 | confidential in-proof | full+reply | yes | 4943 | 18 | 2 | - | 4154 | 4629 | no | 847 B |
| 1x16 | confidential in-proof | full+2tree | yes | 4949 | 18 | 2 | - | 4159 | 4633 | no | 853 B |
| 1x16 | confidential in-proof | full+4credential-shared | yes | 5019 | 20 | 2 | - | 4163 | 4633 | no | 923 B |
| 1x16 | confidential in-proof | full+4credential-disjoint | yes | 5115 | 23 | 2 | - | 4163 | 4633 | no | 1019 B |
| 1x16 | anonymous hidden | min | yes | 4969 | 8 | 1 | - | 4585 | 5134 | no | 873 B |
| 1x16 | anonymous hidden | full | yes | 5439 | 15 | 2 | none | 4746 | 5261 | no | 1343 B |
| 1x16 | anonymous hidden | full+spl | yes | 5807 | 22 | 2 | - | 4878 | 5265 | no | 1711 B |
| 1x16 | anonymous hidden | full+data | yes | 7025 | 15 | 2 | - | 6332 | 6815 | no | 2929 B |
| 1x16 | anonymous hidden | full+reply | yes | 6896 | 15 | 2 | - | 6203 | 6716 | no | 2800 B |
| 1x16 | anonymous hidden | full+2tree | yes | 5445 | 15 | 2 | - | 4751 | 5265 | no | 1349 B |
| 1x16 | anonymous hidden | full+4credential-shared | yes | 5515 | 17 | 2 | - | 4755 | 5265 | no | 1419 B |
| 1x16 | anonymous hidden | full+4credential-disjoint | yes | 5611 | 20 | 2 | - | 4755 | 5265 | no | 1515 B |
| 1x16 | anonymous public owners | min | yes | 4906 | 8 | 1 | - | 4521 | 5037 | no | 810 B |
| 1x16 | anonymous public owners | full | yes | 5568 | 19 | 3 | none | 4682 | 5164 | no | 1472 B |
| 1x16 | anonymous public owners | full+spl | yes | 5936 | 26 | 3 | - | 4814 | 5168 | no | 1840 B |
| 1x16 | anonymous public owners | full+data | yes | 7154 | 19 | 3 | - | 6268 | 6718 | no | 3058 B |
| 1x16 | anonymous public owners | full+reply | yes | 7025 | 19 | 3 | - | 6139 | 6619 | no | 2929 B |
| 1x16 | anonymous public owners | full+2tree | yes | 5574 | 19 | 3 | - | 4687 | 5168 | no | 1478 B |
| 1x16 | anonymous public owners | full+4credential-shared | yes | 5644 | 21 | 3 | - | 4691 | 5168 | no | 1548 B |
| 1x16 | anonymous public owners | full+4credential-disjoint | yes | 5740 | 24 | 3 | - | 4691 | 5168 | no | 1644 B |
| 1x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x8 | confidential signer | min | yes | 2681 | 9 | 1 | - | 2263 | 2496 | yes |  |
| 2x8 | confidential signer | full | yes | 3271 | 20 | 3 | 2 | 2352 | 2541 | yes |  |
| 2x8 | confidential signer | full+spl | yes | 3639 | 27 | 3 | - | 2484 | 2545 | yes |  |
| 2x8 | confidential signer | full+data | yes | 4065 | 20 | 3 | - | 3146 | 3319 | yes |  |
| 2x8 | confidential signer | full+reply | yes | 3271 | 20 | 3 | - | 2352 | 2541 | yes |  |
| 2x8 | confidential signer | full+2tree | yes | 3277 | 20 | 3 | - | 2357 | 2545 | yes |  |
| 2x8 | confidential signer | full+4credential-shared | yes | 3347 | 22 | 3 | - | 2361 | 2545 | yes |  |
| 2x8 | confidential signer | full+4credential-disjoint | yes | 3443 | 25 | 3 | - | 2361 | 2545 | yes |  |
| 2x8 | confidential in-proof | min | yes | 2776 | 9 | 1 | - | 2359 | 2593 | yes |  |
| 2x8 | confidential in-proof | full | yes | 3270 | 19 | 2 | 2 | 2448 | 2638 | yes |  |
| 2x8 | confidential in-proof | full+spl | yes | 3638 | 26 | 2 | - | 2580 | 2642 | yes |  |
| 2x8 | confidential in-proof | full+data | yes | 4064 | 19 | 2 | - | 3242 | 3416 | yes |  |
| 2x8 | confidential in-proof | full+reply | yes | 3270 | 19 | 2 | - | 2448 | 2638 | yes |  |
| 2x8 | confidential in-proof | full+2tree | yes | 3276 | 19 | 2 | - | 2453 | 2642 | yes |  |
| 2x8 | confidential in-proof | full+4credential-shared | yes | 3346 | 21 | 2 | - | 2457 | 2642 | yes |  |
| 2x8 | confidential in-proof | full+4credential-disjoint | yes | 3442 | 24 | 2 | - | 2457 | 2642 | yes |  |
| 2x8 | anonymous hidden | min | yes | 3040 | 9 | 1 | - | 2623 | 2887 | yes |  |
| 2x8 | anonymous hidden | full | yes | 3510 | 16 | 2 | 2 | 2784 | 3014 | yes |  |
| 2x8 | anonymous hidden | full+spl | yes | 3878 | 23 | 2 | - | 2916 | 3018 | yes |  |
| 2x8 | anonymous hidden | full+data | yes | 4304 | 16 | 2 | - | 3578 | 3792 | no | 208 B |
| 2x8 | anonymous hidden | full+reply | yes | 4191 | 16 | 2 | - | 3465 | 3693 | no | 95 B |
| 2x8 | anonymous hidden | full+2tree | yes | 3516 | 16 | 2 | - | 2789 | 3018 | yes |  |
| 2x8 | anonymous hidden | full+4credential-shared | yes | 3586 | 18 | 2 | - | 2793 | 3018 | yes |  |
| 2x8 | anonymous hidden | full+4credential-disjoint | yes | 3682 | 21 | 2 | - | 2793 | 3018 | yes |  |
| 2x8 | anonymous public owners | min | yes | 2977 | 9 | 1 | - | 2559 | 2790 | yes |  |
| 2x8 | anonymous public owners | full | yes | 3639 | 20 | 3 | 2 | 2720 | 2917 | yes |  |
| 2x8 | anonymous public owners | full+spl | yes | 4007 | 27 | 3 | - | 2852 | 2921 | yes |  |
| 2x8 | anonymous public owners | full+data | yes | 4433 | 20 | 3 | - | 3514 | 3695 | no | 337 B |
| 2x8 | anonymous public owners | full+reply | yes | 4320 | 20 | 3 | - | 3401 | 3596 | no | 224 B |
| 2x8 | anonymous public owners | full+2tree | yes | 3645 | 20 | 3 | - | 2725 | 2921 | yes |  |
| 2x8 | anonymous public owners | full+4credential-shared | yes | 3715 | 22 | 3 | - | 2729 | 2921 | yes |  |
| 2x8 | anonymous public owners | full+4credential-disjoint | yes | 3811 | 25 | 3 | - | 2729 | 2921 | yes |  |
| 2x8 | confidential entry | min | yes | 3089 | 9 | 1 | - | 2671 | 2904 | yes |  |
| 2x8 | confidential entry | full | yes | 3679 | 20 | 3 | 2 | 2760 | 2949 | yes |  |
| 2x8 | confidential entry | full+spl | yes | 4047 | 27 | 3 | - | 2892 | 2953 | yes |  |
| 2x8 | confidential entry | full+data | yes | 4473 | 20 | 3 | - | 3554 | 3727 | no | 377 B |
| 2x8 | confidential entry | full+reply | yes | 3679 | 20 | 3 | - | 2760 | 2949 | yes |  |
| 2x8 | confidential entry | full+2tree | yes | 3685 | 20 | 3 | - | 2765 | 2953 | yes |  |
| 2x8 | confidential entry | full+4credential-shared | yes | 3755 | 22 | 3 | - | 2769 | 2953 | yes |  |
| 2x8 | confidential entry | full+4credential-disjoint | yes | 3851 | 25 | 3 | - | 2769 | 2953 | yes |  |
| 2x8 | anonymous entry | min | yes | 3480 | 9 | 1 | - | 3063 | 3295 | yes |  |
| 2x8 | anonymous entry | full | yes | 3950 | 16 | 2 | 1 | 3224 | 3422 | yes |  |
| 2x8 | anonymous entry | full+spl | yes | 4318 | 23 | 2 | - | 3356 | 3426 | no | 222 B |
| 2x8 | anonymous entry | full+data | yes | 4744 | 16 | 2 | - | 4018 | 4200 | no | 648 B |
| 2x8 | anonymous entry | full+reply | yes | 4631 | 16 | 2 | - | 3905 | 4101 | no | 535 B |
| 2x8 | anonymous entry | full+2tree | yes | 3956 | 16 | 2 | - | 3229 | 3426 | yes |  |
| 2x8 | anonymous entry | full+4credential-shared | yes | 4026 | 18 | 2 | - | 3233 | 3426 | yes |  |
| 2x8 | anonymous entry | full+4credential-disjoint | yes | 4122 | 21 | 2 | - | 3233 | 3426 | no | 26 B |
| 2x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x2 | confidential signer | min | yes | 1444 | 10 | 1 | - | 993 | 1011 | yes |  |
| 3x2 | confidential signer | full | yes | 2034 | 21 | 3 | 3 | 1082 | 1056 | yes |  |
| 3x2 | confidential signer | full+spl | yes | 2402 | 28 | 3 | - | 1214 | 1060 | yes |  |
| 3x2 | confidential signer | full+data | yes | 2234 | 21 | 3 | - | 1282 | 1252 | yes |  |
| 3x2 | confidential signer | full+reply | yes | 2034 | 21 | 3 | - | 1082 | 1056 | yes |  |
| 3x2 | confidential signer | full+2tree | yes | 2040 | 21 | 3 | - | 1087 | 1060 | yes |  |
| 3x2 | confidential signer | full+4credential-shared | yes | 2110 | 23 | 3 | - | 1091 | 1060 | yes |  |
| 3x2 | confidential signer | full+4credential-disjoint | yes | 2206 | 26 | 3 | - | 1091 | 1060 | yes |  |
| 3x2 | confidential in-proof | min | yes | 1539 | 10 | 1 | - | 1089 | 1108 | yes |  |
| 3x2 | confidential in-proof | full | yes | 2033 | 20 | 2 | 3 | 1178 | 1153 | yes |  |
| 3x2 | confidential in-proof | full+spl | yes | 2401 | 27 | 2 | - | 1310 | 1157 | yes |  |
| 3x2 | confidential in-proof | full+data | yes | 2233 | 20 | 2 | - | 1378 | 1349 | yes |  |
| 3x2 | confidential in-proof | full+reply | yes | 2033 | 20 | 2 | - | 1178 | 1153 | yes |  |
| 3x2 | confidential in-proof | full+2tree | yes | 2039 | 20 | 2 | - | 1183 | 1157 | yes |  |
| 3x2 | confidential in-proof | full+4credential-shared | yes | 2109 | 22 | 2 | - | 1187 | 1157 | yes |  |
| 3x2 | confidential in-proof | full+4credential-disjoint | yes | 2205 | 25 | 2 | - | 1187 | 1157 | yes |  |
| 3x2 | anonymous hidden | min | yes | 1611 | 10 | 1 | - | 1161 | 1210 | yes |  |
| 3x2 | anonymous hidden | full | yes | 2081 | 17 | 2 | 3 | 1322 | 1337 | yes |  |
| 3x2 | anonymous hidden | full+spl | yes | 2449 | 24 | 2 | - | 1454 | 1341 | yes |  |
| 3x2 | anonymous hidden | full+data | yes | 2281 | 17 | 2 | - | 1522 | 1533 | yes |  |
| 3x2 | anonymous hidden | full+reply | yes | 2180 | 17 | 2 | - | 1421 | 1434 | yes |  |
| 3x2 | anonymous hidden | full+2tree | yes | 2087 | 17 | 2 | - | 1327 | 1341 | yes |  |
| 3x2 | anonymous hidden | full+4credential-shared | yes | 2157 | 19 | 2 | - | 1331 | 1341 | yes |  |
| 3x2 | anonymous hidden | full+4credential-disjoint | yes | 2253 | 22 | 2 | - | 1331 | 1341 | yes |  |
| 3x2 | anonymous public owners | min | yes | 1548 | 10 | 1 | - | 1097 | 1113 | yes |  |
| 3x2 | anonymous public owners | full | yes | 2210 | 21 | 3 | 3 | 1258 | 1240 | yes |  |
| 3x2 | anonymous public owners | full+spl | yes | 2578 | 28 | 3 | - | 1390 | 1244 | yes |  |
| 3x2 | anonymous public owners | full+data | yes | 2410 | 21 | 3 | - | 1458 | 1436 | yes |  |
| 3x2 | anonymous public owners | full+reply | yes | 2309 | 21 | 3 | - | 1357 | 1337 | yes |  |
| 3x2 | anonymous public owners | full+2tree | yes | 2216 | 21 | 3 | - | 1263 | 1244 | yes |  |
| 3x2 | anonymous public owners | full+4credential-shared | yes | 2286 | 23 | 3 | - | 1267 | 1244 | yes |  |
| 3x2 | anonymous public owners | full+4credential-disjoint | yes | 2382 | 26 | 3 | - | 1267 | 1244 | yes |  |
| 3x2 | confidential entry | min | yes | 2052 | 10 | 1 | - | 1601 | 1619 | yes |  |
| 3x2 | confidential entry | full | yes | 2642 | 21 | 3 | 3 | 1690 | 1664 | yes |  |
| 3x2 | confidential entry | full+spl | yes | 3010 | 28 | 3 | - | 1822 | 1668 | yes |  |
| 3x2 | confidential entry | full+data | yes | 2842 | 21 | 3 | - | 1890 | 1860 | yes |  |
| 3x2 | confidential entry | full+reply | yes | 2642 | 21 | 3 | - | 1690 | 1664 | yes |  |
| 3x2 | confidential entry | full+2tree | yes | 2648 | 21 | 3 | - | 1695 | 1668 | yes |  |
| 3x2 | confidential entry | full+4credential-shared | yes | 2718 | 23 | 3 | - | 1699 | 1668 | yes |  |
| 3x2 | confidential entry | full+4credential-disjoint | yes | 2814 | 26 | 3 | - | 1699 | 1668 | yes |  |
| 3x2 | anonymous entry | min | yes | 2251 | 10 | 1 | - | 1801 | 1818 | yes |  |
| 3x2 | anonymous entry | full | yes | 2721 | 17 | 2 | 3 | 1962 | 1945 | yes |  |
| 3x2 | anonymous entry | full+spl | yes | 3089 | 24 | 2 | - | 2094 | 1949 | yes |  |
| 3x2 | anonymous entry | full+data | yes | 2921 | 17 | 2 | - | 2162 | 2141 | yes |  |
| 3x2 | anonymous entry | full+reply | yes | 2820 | 17 | 2 | - | 2061 | 2042 | yes |  |
| 3x2 | anonymous entry | full+2tree | yes | 2727 | 17 | 2 | - | 1967 | 1949 | yes |  |
| 3x2 | anonymous entry | full+4credential-shared | yes | 2797 | 19 | 2 | - | 1971 | 1949 | yes |  |
| 3x2 | anonymous entry | full+4credential-disjoint | yes | 2893 | 22 | 2 | - | 1971 | 1949 | yes |  |
| 3x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x4 | confidential signer | min | yes | 1878 | 10 | 1 | - | 1427 | 1517 | yes |  |
| 3x4 | confidential signer | full | yes | 2468 | 21 | 3 | 3 | 1516 | 1562 | yes |  |
| 3x4 | confidential signer | full+spl | yes | 2836 | 28 | 3 | - | 1648 | 1566 | yes |  |
| 3x4 | confidential signer | full+data | yes | 2866 | 21 | 3 | - | 1914 | 1952 | yes |  |
| 3x4 | confidential signer | full+reply | yes | 2468 | 21 | 3 | - | 1516 | 1562 | yes |  |
| 3x4 | confidential signer | full+2tree | yes | 2474 | 21 | 3 | - | 1521 | 1566 | yes |  |
| 3x4 | confidential signer | full+4credential-shared | yes | 2544 | 23 | 3 | - | 1525 | 1566 | yes |  |
| 3x4 | confidential signer | full+4credential-disjoint | yes | 2640 | 26 | 3 | - | 1525 | 1566 | yes |  |
| 3x4 | confidential in-proof | min | yes | 1973 | 10 | 1 | - | 1523 | 1614 | yes |  |
| 3x4 | confidential in-proof | full | yes | 2467 | 20 | 2 | 3 | 1612 | 1659 | yes |  |
| 3x4 | confidential in-proof | full+spl | yes | 2835 | 27 | 2 | - | 1744 | 1663 | yes |  |
| 3x4 | confidential in-proof | full+data | yes | 2865 | 20 | 2 | - | 2010 | 2049 | yes |  |
| 3x4 | confidential in-proof | full+reply | yes | 2467 | 20 | 2 | - | 1612 | 1659 | yes |  |
| 3x4 | confidential in-proof | full+2tree | yes | 2473 | 20 | 2 | - | 1617 | 1663 | yes |  |
| 3x4 | confidential in-proof | full+4credential-shared | yes | 2543 | 22 | 2 | - | 1621 | 1663 | yes |  |
| 3x4 | confidential in-proof | full+4credential-disjoint | yes | 2639 | 25 | 2 | - | 1621 | 1663 | yes |  |
| 3x4 | anonymous hidden | min | yes | 2109 | 10 | 1 | - | 1659 | 1780 | yes |  |
| 3x4 | anonymous hidden | full | yes | 2579 | 17 | 2 | 3 | 1820 | 1907 | yes |  |
| 3x4 | anonymous hidden | full+spl | yes | 2947 | 24 | 2 | - | 1952 | 1911 | yes |  |
| 3x4 | anonymous hidden | full+data | yes | 2977 | 17 | 2 | - | 2218 | 2297 | yes |  |
| 3x4 | anonymous hidden | full+reply | yes | 2872 | 17 | 2 | - | 2113 | 2198 | yes |  |
| 3x4 | anonymous hidden | full+2tree | yes | 2585 | 17 | 2 | - | 1825 | 1911 | yes |  |
| 3x4 | anonymous hidden | full+4credential-shared | yes | 2655 | 19 | 2 | - | 1829 | 1911 | yes |  |
| 3x4 | anonymous hidden | full+4credential-disjoint | yes | 2751 | 22 | 2 | - | 1829 | 1911 | yes |  |
| 3x4 | anonymous public owners | min | yes | 2046 | 10 | 1 | - | 1595 | 1683 | yes |  |
| 3x4 | anonymous public owners | full | yes | 2708 | 21 | 3 | 3 | 1756 | 1810 | yes |  |
| 3x4 | anonymous public owners | full+spl | yes | 3076 | 28 | 3 | - | 1888 | 1814 | yes |  |
| 3x4 | anonymous public owners | full+data | yes | 3106 | 21 | 3 | - | 2154 | 2200 | yes |  |
| 3x4 | anonymous public owners | full+reply | yes | 3001 | 21 | 3 | - | 2049 | 2101 | yes |  |
| 3x4 | anonymous public owners | full+2tree | yes | 2714 | 21 | 3 | - | 1761 | 1814 | yes |  |
| 3x4 | anonymous public owners | full+4credential-shared | yes | 2784 | 23 | 3 | - | 1765 | 1814 | yes |  |
| 3x4 | anonymous public owners | full+4credential-disjoint | yes | 2880 | 26 | 3 | - | 1765 | 1814 | yes |  |
| 3x4 | confidential entry | min | yes | 2486 | 10 | 1 | - | 2035 | 2125 | yes |  |
| 3x4 | confidential entry | full | yes | 3076 | 21 | 3 | 3 | 2124 | 2170 | yes |  |
| 3x4 | confidential entry | full+spl | yes | 3444 | 28 | 3 | - | 2256 | 2174 | yes |  |
| 3x4 | confidential entry | full+data | yes | 3474 | 21 | 3 | - | 2522 | 2560 | yes |  |
| 3x4 | confidential entry | full+reply | yes | 3076 | 21 | 3 | - | 2124 | 2170 | yes |  |
| 3x4 | confidential entry | full+2tree | yes | 3082 | 21 | 3 | - | 2129 | 2174 | yes |  |
| 3x4 | confidential entry | full+4credential-shared | yes | 3152 | 23 | 3 | - | 2133 | 2174 | yes |  |
| 3x4 | confidential entry | full+4credential-disjoint | yes | 3248 | 26 | 3 | - | 2133 | 2174 | yes |  |
| 3x4 | anonymous entry | min | yes | 2749 | 10 | 1 | - | 2299 | 2388 | yes |  |
| 3x4 | anonymous entry | full | yes | 3219 | 17 | 2 | 3 | 2460 | 2515 | yes |  |
| 3x4 | anonymous entry | full+spl | yes | 3587 | 24 | 2 | - | 2592 | 2519 | yes |  |
| 3x4 | anonymous entry | full+data | yes | 3617 | 17 | 2 | - | 2858 | 2905 | yes |  |
| 3x4 | anonymous entry | full+reply | yes | 3512 | 17 | 2 | - | 2753 | 2806 | yes |  |
| 3x4 | anonymous entry | full+2tree | yes | 3225 | 17 | 2 | - | 2465 | 2519 | yes |  |
| 3x4 | anonymous entry | full+4credential-shared | yes | 3295 | 19 | 2 | - | 2469 | 2519 | yes |  |
| 3x4 | anonymous entry | full+4credential-disjoint | yes | 3391 | 22 | 2 | - | 2469 | 2519 | yes |  |
| 3x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x16 | confidential signer | min | yes | 4419 | 9 | 1 | - | 4001 | 4520 | no | 323 B |
| 2x16 | confidential signer | full | yes | 5009 | 20 | 3 | none | 4090 | 4565 | no | 913 B |
| 2x16 | confidential signer | full+spl | yes | 5377 | 27 | 3 | - | 4222 | 4569 | no | 1281 B |
| 2x16 | confidential signer | full+data | yes | 6595 | 20 | 3 | - | 5676 | 6119 | no | 2499 B |
| 2x16 | confidential signer | full+reply | yes | 5009 | 20 | 3 | - | 4090 | 4565 | no | 913 B |
| 2x16 | confidential signer | full+2tree | yes | 5015 | 20 | 3 | - | 4095 | 4569 | no | 919 B |
| 2x16 | confidential signer | full+4credential-shared | yes | 5085 | 22 | 3 | - | 4099 | 4569 | no | 989 B |
| 2x16 | confidential signer | full+4credential-disjoint | yes | 5181 | 25 | 3 | - | 4099 | 4569 | no | 1085 B |
| 2x16 | confidential in-proof | min | yes | 4514 | 9 | 1 | - | 4097 | 4617 | no | 418 B |
| 2x16 | confidential in-proof | full | yes | 5008 | 19 | 2 | none | 4186 | 4662 | no | 912 B |
| 2x16 | confidential in-proof | full+spl | yes | 5376 | 26 | 2 | - | 4318 | 4666 | no | 1280 B |
| 2x16 | confidential in-proof | full+data | yes | 6594 | 19 | 2 | - | 5772 | 6216 | no | 2498 B |
| 2x16 | confidential in-proof | full+reply | yes | 5008 | 19 | 2 | - | 4186 | 4662 | no | 912 B |
| 2x16 | confidential in-proof | full+2tree | yes | 5014 | 19 | 2 | - | 4191 | 4666 | no | 918 B |
| 2x16 | confidential in-proof | full+4credential-shared | yes | 5084 | 21 | 2 | - | 4195 | 4666 | no | 988 B |
| 2x16 | confidential in-proof | full+4credential-disjoint | yes | 5180 | 24 | 2 | - | 4195 | 4666 | no | 1084 B |
| 2x16 | anonymous hidden | min | yes | 5034 | 9 | 1 | - | 4617 | 5167 | no | 938 B |
| 2x16 | anonymous hidden | full | yes | 5504 | 16 | 2 | none | 4778 | 5294 | no | 1408 B |
| 2x16 | anonymous hidden | full+spl | yes | 5872 | 23 | 2 | - | 4910 | 5298 | no | 1776 B |
| 2x16 | anonymous hidden | full+data | yes | 7090 | 16 | 2 | - | 6364 | 6848 | no | 2994 B |
| 2x16 | anonymous hidden | full+reply | yes | 6961 | 16 | 2 | - | 6235 | 6749 | no | 2865 B |
| 2x16 | anonymous hidden | full+2tree | yes | 5510 | 16 | 2 | - | 4783 | 5298 | no | 1414 B |
| 2x16 | anonymous hidden | full+4credential-shared | yes | 5580 | 18 | 2 | - | 4787 | 5298 | no | 1484 B |
| 2x16 | anonymous hidden | full+4credential-disjoint | yes | 5676 | 21 | 2 | - | 4787 | 5298 | no | 1580 B |
| 2x16 | anonymous public owners | min | yes | 4971 | 9 | 1 | - | 4553 | 5070 | no | 875 B |
| 2x16 | anonymous public owners | full | yes | 5633 | 20 | 3 | none | 4714 | 5197 | no | 1537 B |
| 2x16 | anonymous public owners | full+spl | yes | 6001 | 27 | 3 | - | 4846 | 5201 | no | 1905 B |
| 2x16 | anonymous public owners | full+data | yes | 7219 | 20 | 3 | - | 6300 | 6751 | no | 3123 B |
| 2x16 | anonymous public owners | full+reply | yes | 7090 | 20 | 3 | - | 6171 | 6652 | no | 2994 B |
| 2x16 | anonymous public owners | full+2tree | yes | 5639 | 20 | 3 | - | 4719 | 5201 | no | 1543 B |
| 2x16 | anonymous public owners | full+4credential-shared | yes | 5709 | 22 | 3 | - | 4723 | 5201 | no | 1613 B |
| 2x16 | anonymous public owners | full+4credential-disjoint | yes | 5805 | 25 | 3 | - | 4723 | 5201 | no | 1709 B |
| 2x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x8 | confidential signer | min | yes | 2746 | 10 | 1 | - | 2295 | 2529 | yes |  |
| 3x8 | confidential signer | full | yes | 3336 | 21 | 3 | 3 | 2384 | 2574 | yes |  |
| 3x8 | confidential signer | full+spl | yes | 3704 | 28 | 3 | - | 2516 | 2578 | yes |  |
| 3x8 | confidential signer | full+data | yes | 4130 | 21 | 3 | - | 3178 | 3352 | no | 34 B |
| 3x8 | confidential signer | full+reply | yes | 3336 | 21 | 3 | - | 2384 | 2574 | yes |  |
| 3x8 | confidential signer | full+2tree | yes | 3342 | 21 | 3 | - | 2389 | 2578 | yes |  |
| 3x8 | confidential signer | full+4credential-shared | yes | 3412 | 23 | 3 | - | 2393 | 2578 | yes |  |
| 3x8 | confidential signer | full+4credential-disjoint | yes | 3508 | 26 | 3 | - | 2393 | 2578 | yes |  |
| 3x8 | confidential in-proof | min | yes | 2841 | 10 | 1 | - | 2391 | 2626 | yes |  |
| 3x8 | confidential in-proof | full | yes | 3335 | 20 | 2 | 3 | 2480 | 2671 | yes |  |
| 3x8 | confidential in-proof | full+spl | yes | 3703 | 27 | 2 | - | 2612 | 2675 | yes |  |
| 3x8 | confidential in-proof | full+data | yes | 4129 | 20 | 2 | - | 3274 | 3449 | no | 33 B |
| 3x8 | confidential in-proof | full+reply | yes | 3335 | 20 | 2 | - | 2480 | 2671 | yes |  |
| 3x8 | confidential in-proof | full+2tree | yes | 3341 | 20 | 2 | - | 2485 | 2675 | yes |  |
| 3x8 | confidential in-proof | full+4credential-shared | yes | 3411 | 22 | 2 | - | 2489 | 2675 | yes |  |
| 3x8 | confidential in-proof | full+4credential-disjoint | yes | 3507 | 25 | 2 | - | 2489 | 2675 | yes |  |
| 3x8 | anonymous hidden | min | yes | 3105 | 10 | 1 | - | 2655 | 2920 | yes |  |
| 3x8 | anonymous hidden | full | yes | 3575 | 17 | 2 | 3 | 2816 | 3047 | yes |  |
| 3x8 | anonymous hidden | full+spl | yes | 3943 | 24 | 2 | - | 2948 | 3051 | yes |  |
| 3x8 | anonymous hidden | full+data | yes | 4369 | 17 | 2 | - | 3610 | 3825 | no | 273 B |
| 3x8 | anonymous hidden | full+reply | yes | 4256 | 17 | 2 | - | 3497 | 3726 | no | 160 B |
| 3x8 | anonymous hidden | full+2tree | yes | 3581 | 17 | 2 | - | 2821 | 3051 | yes |  |
| 3x8 | anonymous hidden | full+4credential-shared | yes | 3651 | 19 | 2 | - | 2825 | 3051 | yes |  |
| 3x8 | anonymous hidden | full+4credential-disjoint | yes | 3747 | 22 | 2 | - | 2825 | 3051 | yes |  |
| 3x8 | anonymous public owners | min | yes | 3042 | 10 | 1 | - | 2591 | 2823 | yes |  |
| 3x8 | anonymous public owners | full | yes | 3704 | 21 | 3 | 3 | 2752 | 2950 | yes |  |
| 3x8 | anonymous public owners | full+spl | yes | 4072 | 28 | 3 | - | 2884 | 2954 | yes |  |
| 3x8 | anonymous public owners | full+data | yes | 4498 | 21 | 3 | - | 3546 | 3728 | no | 402 B |
| 3x8 | anonymous public owners | full+reply | yes | 4385 | 21 | 3 | - | 3433 | 3629 | no | 289 B |
| 3x8 | anonymous public owners | full+2tree | yes | 3710 | 21 | 3 | - | 2757 | 2954 | yes |  |
| 3x8 | anonymous public owners | full+4credential-shared | yes | 3780 | 23 | 3 | - | 2761 | 2954 | yes |  |
| 3x8 | anonymous public owners | full+4credential-disjoint | yes | 3876 | 26 | 3 | - | 2761 | 2954 | yes |  |
| 3x8 | confidential entry | min | yes | 3354 | 10 | 1 | - | 2903 | 3137 | yes |  |
| 3x8 | confidential entry | full | yes | 3944 | 21 | 3 | 2 | 2992 | 3182 | yes |  |
| 3x8 | confidential entry | full+spl | yes | 4312 | 28 | 3 | - | 3124 | 3186 | no | 216 B |
| 3x8 | confidential entry | full+data | yes | 4738 | 21 | 3 | - | 3786 | 3960 | no | 642 B |
| 3x8 | confidential entry | full+reply | yes | 3944 | 21 | 3 | - | 2992 | 3182 | yes |  |
| 3x8 | confidential entry | full+2tree | yes | 3950 | 21 | 3 | - | 2997 | 3186 | yes |  |
| 3x8 | confidential entry | full+4credential-shared | yes | 4020 | 23 | 3 | - | 3001 | 3186 | yes |  |
| 3x8 | confidential entry | full+4credential-disjoint | yes | 4116 | 26 | 3 | - | 3001 | 3186 | no | 20 B |
| 3x8 | anonymous entry | min | yes | 3745 | 10 | 1 | - | 3295 | 3528 | yes |  |
| 3x8 | anonymous entry | full | yes | 4215 | 17 | 2 | none | 3456 | 3655 | no | 119 B |
| 3x8 | anonymous entry | full+spl | yes | 4583 | 24 | 2 | - | 3588 | 3659 | no | 487 B |
| 3x8 | anonymous entry | full+data | yes | 5009 | 17 | 2 | - | 4250 | 4433 | no | 913 B |
| 3x8 | anonymous entry | full+reply | yes | 4896 | 17 | 2 | - | 4137 | 4334 | no | 800 B |
| 3x8 | anonymous entry | full+2tree | yes | 4221 | 17 | 2 | - | 3461 | 3659 | no | 125 B |
| 3x8 | anonymous entry | full+4credential-shared | yes | 4291 | 19 | 2 | - | 3465 | 3659 | no | 195 B |
| 3x8 | anonymous entry | full+4credential-disjoint | yes | 4387 | 22 | 2 | - | 3465 | 3659 | no | 291 B |
| 3x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x2 | confidential signer | min | yes | 1509 | 11 | 1 | - | 1025 | 1044 | yes |  |
| 4x2 | confidential signer | full | yes | 2099 | 22 | 3 | 4 | 1114 | 1089 | yes |  |
| 4x2 | confidential signer | full+spl | yes | 2467 | 29 | 3 | - | 1246 | 1093 | yes |  |
| 4x2 | confidential signer | full+data | yes | 2299 | 22 | 3 | - | 1314 | 1285 | yes |  |
| 4x2 | confidential signer | full+reply | yes | 2099 | 22 | 3 | - | 1114 | 1089 | yes |  |
| 4x2 | confidential signer | full+2tree | yes | 2105 | 22 | 3 | - | 1119 | 1093 | yes |  |
| 4x2 | confidential signer | full+4credential-shared | yes | 2175 | 24 | 3 | - | 1123 | 1093 | yes |  |
| 4x2 | confidential signer | full+4credential-disjoint | yes | 2271 | 27 | 3 | - | 1123 | 1093 | yes |  |
| 4x2 | confidential in-proof | min | yes | 1604 | 11 | 1 | - | 1121 | 1141 | yes |  |
| 4x2 | confidential in-proof | full | yes | 2098 | 21 | 2 | 4 | 1210 | 1186 | yes |  |
| 4x2 | confidential in-proof | full+spl | yes | 2466 | 28 | 2 | - | 1342 | 1190 | yes |  |
| 4x2 | confidential in-proof | full+data | yes | 2298 | 21 | 2 | - | 1410 | 1382 | yes |  |
| 4x2 | confidential in-proof | full+reply | yes | 2098 | 21 | 2 | - | 1210 | 1186 | yes |  |
| 4x2 | confidential in-proof | full+2tree | yes | 2104 | 21 | 2 | - | 1215 | 1190 | yes |  |
| 4x2 | confidential in-proof | full+4credential-shared | yes | 2174 | 23 | 2 | - | 1219 | 1190 | yes |  |
| 4x2 | confidential in-proof | full+4credential-disjoint | yes | 2270 | 26 | 2 | - | 1219 | 1190 | yes |  |
| 4x2 | anonymous hidden | min | yes | 1676 | 11 | 1 | - | 1193 | 1243 | yes |  |
| 4x2 | anonymous hidden | full | yes | 2146 | 18 | 2 | 4 | 1354 | 1370 | yes |  |
| 4x2 | anonymous hidden | full+spl | yes | 2514 | 25 | 2 | - | 1486 | 1374 | yes |  |
| 4x2 | anonymous hidden | full+data | yes | 2346 | 18 | 2 | - | 1554 | 1566 | yes |  |
| 4x2 | anonymous hidden | full+reply | yes | 2245 | 18 | 2 | - | 1453 | 1467 | yes |  |
| 4x2 | anonymous hidden | full+2tree | yes | 2152 | 18 | 2 | - | 1359 | 1374 | yes |  |
| 4x2 | anonymous hidden | full+4credential-shared | yes | 2222 | 20 | 2 | - | 1363 | 1374 | yes |  |
| 4x2 | anonymous hidden | full+4credential-disjoint | yes | 2318 | 23 | 2 | - | 1363 | 1374 | yes |  |
| 4x2 | anonymous public owners | min | yes | 1613 | 11 | 1 | - | 1129 | 1146 | yes |  |
| 4x2 | anonymous public owners | full | yes | 2275 | 22 | 3 | 4 | 1290 | 1273 | yes |  |
| 4x2 | anonymous public owners | full+spl | yes | 2643 | 29 | 3 | - | 1422 | 1277 | yes |  |
| 4x2 | anonymous public owners | full+data | yes | 2475 | 22 | 3 | - | 1490 | 1469 | yes |  |
| 4x2 | anonymous public owners | full+reply | yes | 2374 | 22 | 3 | - | 1389 | 1370 | yes |  |
| 4x2 | anonymous public owners | full+2tree | yes | 2281 | 22 | 3 | - | 1295 | 1277 | yes |  |
| 4x2 | anonymous public owners | full+4credential-shared | yes | 2351 | 24 | 3 | - | 1299 | 1277 | yes |  |
| 4x2 | anonymous public owners | full+4credential-disjoint | yes | 2447 | 27 | 3 | - | 1299 | 1277 | yes |  |
| 4x2 | confidential entry | min | yes | 2317 | 11 | 1 | - | 1833 | 1852 | yes |  |
| 4x2 | confidential entry | full | yes | 2907 | 22 | 3 | 4 | 1922 | 1897 | yes |  |
| 4x2 | confidential entry | full+spl | yes | 3275 | 29 | 3 | - | 2054 | 1901 | yes |  |
| 4x2 | confidential entry | full+data | yes | 3107 | 22 | 3 | - | 2122 | 2093 | yes |  |
| 4x2 | confidential entry | full+reply | yes | 2907 | 22 | 3 | - | 1922 | 1897 | yes |  |
| 4x2 | confidential entry | full+2tree | yes | 2913 | 22 | 3 | - | 1927 | 1901 | yes |  |
| 4x2 | confidential entry | full+4credential-shared | yes | 2983 | 24 | 3 | - | 1931 | 1901 | yes |  |
| 4x2 | confidential entry | full+4credential-disjoint | yes | 3079 | 27 | 3 | - | 1931 | 1901 | yes |  |
| 4x2 | anonymous entry | min | yes | 2516 | 11 | 1 | - | 2033 | 2051 | yes |  |
| 4x2 | anonymous entry | full | yes | 2986 | 18 | 2 | 4 | 2194 | 2178 | yes |  |
| 4x2 | anonymous entry | full+spl | yes | 3354 | 25 | 2 | - | 2326 | 2182 | yes |  |
| 4x2 | anonymous entry | full+data | yes | 3186 | 18 | 2 | - | 2394 | 2374 | yes |  |
| 4x2 | anonymous entry | full+reply | yes | 3085 | 18 | 2 | - | 2293 | 2275 | yes |  |
| 4x2 | anonymous entry | full+2tree | yes | 2992 | 18 | 2 | - | 2199 | 2182 | yes |  |
| 4x2 | anonymous entry | full+4credential-shared | yes | 3062 | 20 | 2 | - | 2203 | 2182 | yes |  |
| 4x2 | anonymous entry | full+4credential-disjoint | yes | 3158 | 23 | 2 | - | 2203 | 2182 | yes |  |
| 4x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x4 | confidential signer | min | yes | 1943 | 11 | 1 | - | 1459 | 1550 | yes |  |
| 4x4 | confidential signer | full | yes | 2533 | 22 | 3 | 4 | 1548 | 1595 | yes |  |
| 4x4 | confidential signer | full+spl | yes | 2901 | 29 | 3 | - | 1680 | 1599 | yes |  |
| 4x4 | confidential signer | full+data | yes | 2931 | 22 | 3 | - | 1946 | 1985 | yes |  |
| 4x4 | confidential signer | full+reply | yes | 2533 | 22 | 3 | - | 1548 | 1595 | yes |  |
| 4x4 | confidential signer | full+2tree | yes | 2539 | 22 | 3 | - | 1553 | 1599 | yes |  |
| 4x4 | confidential signer | full+4credential-shared | yes | 2609 | 24 | 3 | - | 1557 | 1599 | yes |  |
| 4x4 | confidential signer | full+4credential-disjoint | yes | 2705 | 27 | 3 | - | 1557 | 1599 | yes |  |
| 4x4 | confidential in-proof | min | yes | 2038 | 11 | 1 | - | 1555 | 1647 | yes |  |
| 4x4 | confidential in-proof | full | yes | 2532 | 21 | 2 | 4 | 1644 | 1692 | yes |  |
| 4x4 | confidential in-proof | full+spl | yes | 2900 | 28 | 2 | - | 1776 | 1696 | yes |  |
| 4x4 | confidential in-proof | full+data | yes | 2930 | 21 | 2 | - | 2042 | 2082 | yes |  |
| 4x4 | confidential in-proof | full+reply | yes | 2532 | 21 | 2 | - | 1644 | 1692 | yes |  |
| 4x4 | confidential in-proof | full+2tree | yes | 2538 | 21 | 2 | - | 1649 | 1696 | yes |  |
| 4x4 | confidential in-proof | full+4credential-shared | yes | 2608 | 23 | 2 | - | 1653 | 1696 | yes |  |
| 4x4 | confidential in-proof | full+4credential-disjoint | yes | 2704 | 26 | 2 | - | 1653 | 1696 | yes |  |
| 4x4 | anonymous hidden | min | yes | 2174 | 11 | 1 | - | 1691 | 1813 | yes |  |
| 4x4 | anonymous hidden | full | yes | 2644 | 18 | 2 | 4 | 1852 | 1940 | yes |  |
| 4x4 | anonymous hidden | full+spl | yes | 3012 | 25 | 2 | - | 1984 | 1944 | yes |  |
| 4x4 | anonymous hidden | full+data | yes | 3042 | 18 | 2 | - | 2250 | 2330 | yes |  |
| 4x4 | anonymous hidden | full+reply | yes | 2937 | 18 | 2 | - | 2145 | 2231 | yes |  |
| 4x4 | anonymous hidden | full+2tree | yes | 2650 | 18 | 2 | - | 1857 | 1944 | yes |  |
| 4x4 | anonymous hidden | full+4credential-shared | yes | 2720 | 20 | 2 | - | 1861 | 1944 | yes |  |
| 4x4 | anonymous hidden | full+4credential-disjoint | yes | 2816 | 23 | 2 | - | 1861 | 1944 | yes |  |
| 4x4 | anonymous public owners | min | yes | 2111 | 11 | 1 | - | 1627 | 1716 | yes |  |
| 4x4 | anonymous public owners | full | yes | 2773 | 22 | 3 | 4 | 1788 | 1843 | yes |  |
| 4x4 | anonymous public owners | full+spl | yes | 3141 | 29 | 3 | - | 1920 | 1847 | yes |  |
| 4x4 | anonymous public owners | full+data | yes | 3171 | 22 | 3 | - | 2186 | 2233 | yes |  |
| 4x4 | anonymous public owners | full+reply | yes | 3066 | 22 | 3 | - | 2081 | 2134 | yes |  |
| 4x4 | anonymous public owners | full+2tree | yes | 2779 | 22 | 3 | - | 1793 | 1847 | yes |  |
| 4x4 | anonymous public owners | full+4credential-shared | yes | 2849 | 24 | 3 | - | 1797 | 1847 | yes |  |
| 4x4 | anonymous public owners | full+4credential-disjoint | yes | 2945 | 27 | 3 | - | 1797 | 1847 | yes |  |
| 4x4 | confidential entry | min | yes | 2751 | 11 | 1 | - | 2267 | 2358 | yes |  |
| 4x4 | confidential entry | full | yes | 3341 | 22 | 3 | 4 | 2356 | 2403 | yes |  |
| 4x4 | confidential entry | full+spl | yes | 3709 | 29 | 3 | - | 2488 | 2407 | yes |  |
| 4x4 | confidential entry | full+data | yes | 3739 | 22 | 3 | - | 2754 | 2793 | yes |  |
| 4x4 | confidential entry | full+reply | yes | 3341 | 22 | 3 | - | 2356 | 2403 | yes |  |
| 4x4 | confidential entry | full+2tree | yes | 3347 | 22 | 3 | - | 2361 | 2407 | yes |  |
| 4x4 | confidential entry | full+4credential-shared | yes | 3417 | 24 | 3 | - | 2365 | 2407 | yes |  |
| 4x4 | confidential entry | full+4credential-disjoint | yes | 3513 | 27 | 3 | - | 2365 | 2407 | yes |  |
| 4x4 | anonymous entry | min | yes | 3014 | 11 | 1 | - | 2531 | 2621 | yes |  |
| 4x4 | anonymous entry | full | yes | 3484 | 18 | 2 | 4 | 2692 | 2748 | yes |  |
| 4x4 | anonymous entry | full+spl | yes | 3852 | 25 | 2 | - | 2824 | 2752 | yes |  |
| 4x4 | anonymous entry | full+data | yes | 3882 | 18 | 2 | - | 3090 | 3138 | yes |  |
| 4x4 | anonymous entry | full+reply | yes | 3777 | 18 | 2 | - | 2985 | 3039 | yes |  |
| 4x4 | anonymous entry | full+2tree | yes | 3490 | 18 | 2 | - | 2697 | 2752 | yes |  |
| 4x4 | anonymous entry | full+4credential-shared | yes | 3560 | 20 | 2 | - | 2701 | 2752 | yes |  |
| 4x4 | anonymous entry | full+4credential-disjoint | yes | 3656 | 23 | 2 | - | 2701 | 2752 | yes |  |
| 4x4 | delegate | min | yes | 1943 | 11 | 1 | - | 1459 | 1550 | yes |  |
| 4x4 | delegate | full | yes | 2321 | 18 | 2 | - | 1532 | 1595 | yes |  |
| 4x4 | delegate | full+spl | yes | 2561 | 25 | 2 | - | 1536 | 1599 | yes |  |
| 4x4 | delegate | full+data | yes | 2719 | 18 | 2 | - | 1930 | 1985 | yes |  |
| 4x4 | delegate | full+reply | yes | 2321 | 18 | 2 | - | 1532 | 1595 | yes |  |
| 4x4 | delegate | full+2tree | yes | 2327 | 18 | 2 | - | 1537 | 1599 | yes |  |
| 4x4 | delegate | full+4credential-shared | yes | 2397 | 20 | 2 | - | 1541 | 1599 | yes |  |
| 4x4 | delegate | full+4credential-disjoint | yes | 2493 | 23 | 2 | - | 1541 | 1599 | yes |  |
| 4x4 | anonymous delegate | min | yes | 2111 | 11 | 1 | - | 1627 | 1716 | yes |  |
| 4x4 | anonymous delegate | full | yes | 2561 | 18 | 2 | - | 1772 | 1843 | yes |  |
| 4x4 | anonymous delegate | full+spl | yes | 2801 | 25 | 2 | - | 1776 | 1847 | yes |  |
| 4x4 | anonymous delegate | full+data | yes | 2959 | 18 | 2 | - | 2170 | 2233 | yes |  |
| 4x4 | anonymous delegate | full+reply | yes | 2854 | 18 | 2 | - | 2065 | 2134 | yes |  |
| 4x4 | anonymous delegate | full+2tree | yes | 2567 | 18 | 2 | - | 1777 | 1847 | yes |  |
| 4x4 | anonymous delegate | full+4credential-shared | yes | 2637 | 20 | 2 | - | 1781 | 1847 | yes |  |
| 4x4 | anonymous delegate | full+4credential-disjoint | yes | 2733 | 23 | 2 | - | 1781 | 1847 | yes |  |
| 4x8 | confidential signer | min | yes | 2811 | 11 | 1 | - | 2327 | 2562 | yes |  |
| 4x8 | confidential signer | full | yes | 3401 | 22 | 3 | 4 | 2416 | 2607 | yes |  |
| 4x8 | confidential signer | full+spl | yes | 3769 | 29 | 3 | - | 2548 | 2611 | yes |  |
| 4x8 | confidential signer | full+data | yes | 4195 | 22 | 3 | - | 3210 | 3385 | no | 99 B |
| 4x8 | confidential signer | full+reply | yes | 3401 | 22 | 3 | - | 2416 | 2607 | yes |  |
| 4x8 | confidential signer | full+2tree | yes | 3407 | 22 | 3 | - | 2421 | 2611 | yes |  |
| 4x8 | confidential signer | full+4credential-shared | yes | 3477 | 24 | 3 | - | 2425 | 2611 | yes |  |
| 4x8 | confidential signer | full+4credential-disjoint | yes | 3573 | 27 | 3 | - | 2425 | 2611 | yes |  |
| 4x8 | confidential in-proof | min | yes | 2906 | 11 | 1 | - | 2423 | 2659 | yes |  |
| 4x8 | confidential in-proof | full | yes | 3400 | 21 | 2 | 4 | 2512 | 2704 | yes |  |
| 4x8 | confidential in-proof | full+spl | yes | 3768 | 28 | 2 | - | 2644 | 2708 | yes |  |
| 4x8 | confidential in-proof | full+data | yes | 4194 | 21 | 2 | - | 3306 | 3482 | no | 98 B |
| 4x8 | confidential in-proof | full+reply | yes | 3400 | 21 | 2 | - | 2512 | 2704 | yes |  |
| 4x8 | confidential in-proof | full+2tree | yes | 3406 | 21 | 2 | - | 2517 | 2708 | yes |  |
| 4x8 | confidential in-proof | full+4credential-shared | yes | 3476 | 23 | 2 | - | 2521 | 2708 | yes |  |
| 4x8 | confidential in-proof | full+4credential-disjoint | yes | 3572 | 26 | 2 | - | 2521 | 2708 | yes |  |
| 4x8 | anonymous hidden | min | yes | 3170 | 11 | 1 | - | 2687 | 2953 | yes |  |
| 4x8 | anonymous hidden | full | yes | 3640 | 18 | 2 | 4 | 2848 | 3080 | yes |  |
| 4x8 | anonymous hidden | full+spl | yes | 4008 | 25 | 2 | - | 2980 | 3084 | yes |  |
| 4x8 | anonymous hidden | full+data | yes | 4434 | 18 | 2 | - | 3642 | 3858 | no | 338 B |
| 4x8 | anonymous hidden | full+reply | yes | 4321 | 18 | 2 | - | 3529 | 3759 | no | 225 B |
| 4x8 | anonymous hidden | full+2tree | yes | 3646 | 18 | 2 | - | 2853 | 3084 | yes |  |
| 4x8 | anonymous hidden | full+4credential-shared | yes | 3716 | 20 | 2 | - | 2857 | 3084 | yes |  |
| 4x8 | anonymous hidden | full+4credential-disjoint | yes | 3812 | 23 | 2 | - | 2857 | 3084 | yes |  |
| 4x8 | anonymous public owners | min | yes | 3107 | 11 | 1 | - | 2623 | 2856 | yes |  |
| 4x8 | anonymous public owners | full | yes | 3769 | 22 | 3 | 4 | 2784 | 2983 | yes |  |
| 4x8 | anonymous public owners | full+spl | yes | 4137 | 29 | 3 | - | 2916 | 2987 | no | 41 B |
| 4x8 | anonymous public owners | full+data | yes | 4563 | 22 | 3 | - | 3578 | 3761 | no | 467 B |
| 4x8 | anonymous public owners | full+reply | yes | 4450 | 22 | 3 | - | 3465 | 3662 | no | 354 B |
| 4x8 | anonymous public owners | full+2tree | yes | 3775 | 22 | 3 | - | 2789 | 2987 | yes |  |
| 4x8 | anonymous public owners | full+4credential-shared | yes | 3845 | 24 | 3 | - | 2793 | 2987 | yes |  |
| 4x8 | anonymous public owners | full+4credential-disjoint | yes | 3941 | 27 | 3 | - | 2793 | 2987 | yes |  |
| 4x8 | confidential entry | min | yes | 3619 | 11 | 1 | - | 3135 | 3370 | yes |  |
| 4x8 | confidential entry | full | yes | 4209 | 22 | 3 | none | 3224 | 3415 | no | 113 B |
| 4x8 | confidential entry | full+spl | yes | 4577 | 29 | 3 | - | 3356 | 3419 | no | 481 B |
| 4x8 | confidential entry | full+data | yes | 5003 | 22 | 3 | - | 4018 | 4193 | no | 907 B |
| 4x8 | confidential entry | full+reply | yes | 4209 | 22 | 3 | - | 3224 | 3415 | no | 113 B |
| 4x8 | confidential entry | full+2tree | yes | 4215 | 22 | 3 | - | 3229 | 3419 | no | 119 B |
| 4x8 | confidential entry | full+4credential-shared | yes | 4285 | 24 | 3 | - | 3233 | 3419 | no | 189 B |
| 4x8 | confidential entry | full+4credential-disjoint | yes | 4381 | 27 | 3 | - | 3233 | 3419 | no | 285 B |
| 4x8 | anonymous entry | min | yes | 4010 | 11 | 1 | - | 3527 | 3761 | yes |  |
| 4x8 | anonymous entry | full | yes | 4480 | 18 | 2 | none | 3688 | 3888 | no | 384 B |
| 4x8 | anonymous entry | full+spl | yes | 4848 | 25 | 2 | - | 3820 | 3892 | no | 752 B |
| 4x8 | anonymous entry | full+data | yes | 5274 | 18 | 2 | - | 4482 | 4666 | no | 1178 B |
| 4x8 | anonymous entry | full+reply | yes | 5161 | 18 | 2 | - | 4369 | 4567 | no | 1065 B |
| 4x8 | anonymous entry | full+2tree | yes | 4486 | 18 | 2 | - | 3693 | 3892 | no | 390 B |
| 4x8 | anonymous entry | full+4credential-shared | yes | 4556 | 20 | 2 | - | 3697 | 3892 | no | 460 B |
| 4x8 | anonymous entry | full+4credential-disjoint | yes | 4652 | 23 | 2 | - | 3697 | 3892 | no | 556 B |
| 4x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x2 | confidential signer | min | yes | 1574 | 12 | 1 | - | 1057 | 1077 | yes |  |
| 5x2 | confidential signer | full | yes | 2164 | 23 | 3 | 5 | 1146 | 1122 | yes |  |
| 5x2 | confidential signer | full+spl | yes | 2532 | 30 | 3 | - | 1278 | 1126 | yes |  |
| 5x2 | confidential signer | full+data | yes | 2364 | 23 | 3 | - | 1346 | 1318 | yes |  |
| 5x2 | confidential signer | full+reply | yes | 2164 | 23 | 3 | - | 1146 | 1122 | yes |  |
| 5x2 | confidential signer | full+2tree | yes | 2170 | 23 | 3 | - | 1151 | 1126 | yes |  |
| 5x2 | confidential signer | full+4credential-shared | yes | 2240 | 25 | 3 | - | 1155 | 1126 | yes |  |
| 5x2 | confidential signer | full+4credential-disjoint | yes | 2336 | 28 | 3 | - | 1155 | 1126 | yes |  |
| 5x2 | confidential in-proof | min | yes | 1669 | 12 | 1 | - | 1153 | 1174 | yes |  |
| 5x2 | confidential in-proof | full | yes | 2163 | 22 | 2 | 5 | 1242 | 1219 | yes |  |
| 5x2 | confidential in-proof | full+spl | yes | 2531 | 29 | 2 | - | 1374 | 1223 | yes |  |
| 5x2 | confidential in-proof | full+data | yes | 2363 | 22 | 2 | - | 1442 | 1415 | yes |  |
| 5x2 | confidential in-proof | full+reply | yes | 2163 | 22 | 2 | - | 1242 | 1219 | yes |  |
| 5x2 | confidential in-proof | full+2tree | yes | 2169 | 22 | 2 | - | 1247 | 1223 | yes |  |
| 5x2 | confidential in-proof | full+4credential-shared | yes | 2239 | 24 | 2 | - | 1251 | 1223 | yes |  |
| 5x2 | confidential in-proof | full+4credential-disjoint | yes | 2335 | 27 | 2 | - | 1251 | 1223 | yes |  |
| 5x2 | anonymous hidden | min | yes | 1741 | 12 | 1 | - | 1225 | 1276 | yes |  |
| 5x2 | anonymous hidden | full | yes | 2211 | 19 | 2 | 5 | 1386 | 1403 | yes |  |
| 5x2 | anonymous hidden | full+spl | yes | 2579 | 26 | 2 | - | 1518 | 1407 | yes |  |
| 5x2 | anonymous hidden | full+data | yes | 2411 | 19 | 2 | - | 1586 | 1599 | yes |  |
| 5x2 | anonymous hidden | full+reply | yes | 2310 | 19 | 2 | - | 1485 | 1500 | yes |  |
| 5x2 | anonymous hidden | full+2tree | yes | 2217 | 19 | 2 | - | 1391 | 1407 | yes |  |
| 5x2 | anonymous hidden | full+4credential-shared | yes | 2287 | 21 | 2 | - | 1395 | 1407 | yes |  |
| 5x2 | anonymous hidden | full+4credential-disjoint | yes | 2383 | 24 | 2 | - | 1395 | 1407 | yes |  |
| 5x2 | anonymous public owners | min | yes | 1678 | 12 | 1 | - | 1161 | 1179 | yes |  |
| 5x2 | anonymous public owners | full | yes | 2340 | 23 | 3 | 5 | 1322 | 1306 | yes |  |
| 5x2 | anonymous public owners | full+spl | yes | 2708 | 30 | 3 | - | 1454 | 1310 | yes |  |
| 5x2 | anonymous public owners | full+data | yes | 2540 | 23 | 3 | - | 1522 | 1502 | yes |  |
| 5x2 | anonymous public owners | full+reply | yes | 2439 | 23 | 3 | - | 1421 | 1403 | yes |  |
| 5x2 | anonymous public owners | full+2tree | yes | 2346 | 23 | 3 | - | 1327 | 1310 | yes |  |
| 5x2 | anonymous public owners | full+4credential-shared | yes | 2416 | 25 | 3 | - | 1331 | 1310 | yes |  |
| 5x2 | anonymous public owners | full+4credential-disjoint | yes | 2512 | 28 | 3 | - | 1331 | 1310 | yes |  |
| 5x2 | confidential entry | min | yes | 2582 | 12 | 1 | - | 2065 | 2085 | yes |  |
| 5x2 | confidential entry | full | yes | 3172 | 23 | 3 | 5 | 2154 | 2130 | yes |  |
| 5x2 | confidential entry | full+spl | yes | 3540 | 30 | 3 | - | 2286 | 2134 | yes |  |
| 5x2 | confidential entry | full+data | yes | 3372 | 23 | 3 | - | 2354 | 2326 | yes |  |
| 5x2 | confidential entry | full+reply | yes | 3172 | 23 | 3 | - | 2154 | 2130 | yes |  |
| 5x2 | confidential entry | full+2tree | yes | 3178 | 23 | 3 | - | 2159 | 2134 | yes |  |
| 5x2 | confidential entry | full+4credential-shared | yes | 3248 | 25 | 3 | - | 2163 | 2134 | yes |  |
| 5x2 | confidential entry | full+4credential-disjoint | yes | 3344 | 28 | 3 | - | 2163 | 2134 | yes |  |
| 5x2 | anonymous entry | min | yes | 2781 | 12 | 1 | - | 2265 | 2284 | yes |  |
| 5x2 | anonymous entry | full | yes | 3251 | 19 | 2 | 5 | 2426 | 2411 | yes |  |
| 5x2 | anonymous entry | full+spl | yes | 3619 | 26 | 2 | - | 2558 | 2415 | yes |  |
| 5x2 | anonymous entry | full+data | yes | 3451 | 19 | 2 | - | 2626 | 2607 | yes |  |
| 5x2 | anonymous entry | full+reply | yes | 3350 | 19 | 2 | - | 2525 | 2508 | yes |  |
| 5x2 | anonymous entry | full+2tree | yes | 3257 | 19 | 2 | - | 2431 | 2415 | yes |  |
| 5x2 | anonymous entry | full+4credential-shared | yes | 3327 | 21 | 2 | - | 2435 | 2415 | yes |  |
| 5x2 | anonymous entry | full+4credential-disjoint | yes | 3423 | 24 | 2 | - | 2435 | 2415 | yes |  |
| 5x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x4 | confidential signer | min | yes | 2008 | 12 | 1 | - | 1491 | 1583 | yes |  |
| 5x4 | confidential signer | full | yes | 2598 | 23 | 3 | 5 | 1580 | 1628 | yes |  |
| 5x4 | confidential signer | full+spl | yes | 2966 | 30 | 3 | - | 1712 | 1632 | yes |  |
| 5x4 | confidential signer | full+data | yes | 2996 | 23 | 3 | - | 1978 | 2018 | yes |  |
| 5x4 | confidential signer | full+reply | yes | 2598 | 23 | 3 | - | 1580 | 1628 | yes |  |
| 5x4 | confidential signer | full+2tree | yes | 2604 | 23 | 3 | - | 1585 | 1632 | yes |  |
| 5x4 | confidential signer | full+4credential-shared | yes | 2674 | 25 | 3 | - | 1589 | 1632 | yes |  |
| 5x4 | confidential signer | full+4credential-disjoint | yes | 2770 | 28 | 3 | - | 1589 | 1632 | yes |  |
| 5x4 | confidential in-proof | min | yes | 2103 | 12 | 1 | - | 1587 | 1680 | yes |  |
| 5x4 | confidential in-proof | full | yes | 2597 | 22 | 2 | 5 | 1676 | 1725 | yes |  |
| 5x4 | confidential in-proof | full+spl | yes | 2965 | 29 | 2 | - | 1808 | 1729 | yes |  |
| 5x4 | confidential in-proof | full+data | yes | 2995 | 22 | 2 | - | 2074 | 2115 | yes |  |
| 5x4 | confidential in-proof | full+reply | yes | 2597 | 22 | 2 | - | 1676 | 1725 | yes |  |
| 5x4 | confidential in-proof | full+2tree | yes | 2603 | 22 | 2 | - | 1681 | 1729 | yes |  |
| 5x4 | confidential in-proof | full+4credential-shared | yes | 2673 | 24 | 2 | - | 1685 | 1729 | yes |  |
| 5x4 | confidential in-proof | full+4credential-disjoint | yes | 2769 | 27 | 2 | - | 1685 | 1729 | yes |  |
| 5x4 | anonymous hidden | min | yes | 2239 | 12 | 1 | - | 1723 | 1846 | yes |  |
| 5x4 | anonymous hidden | full | yes | 2709 | 19 | 2 | 5 | 1884 | 1973 | yes |  |
| 5x4 | anonymous hidden | full+spl | yes | 3077 | 26 | 2 | - | 2016 | 1977 | yes |  |
| 5x4 | anonymous hidden | full+data | yes | 3107 | 19 | 2 | - | 2282 | 2363 | yes |  |
| 5x4 | anonymous hidden | full+reply | yes | 3002 | 19 | 2 | - | 2177 | 2264 | yes |  |
| 5x4 | anonymous hidden | full+2tree | yes | 2715 | 19 | 2 | - | 1889 | 1977 | yes |  |
| 5x4 | anonymous hidden | full+4credential-shared | yes | 2785 | 21 | 2 | - | 1893 | 1977 | yes |  |
| 5x4 | anonymous hidden | full+4credential-disjoint | yes | 2881 | 24 | 2 | - | 1893 | 1977 | yes |  |
| 5x4 | anonymous public owners | min | yes | 2176 | 12 | 1 | - | 1659 | 1749 | yes |  |
| 5x4 | anonymous public owners | full | yes | 2838 | 23 | 3 | 5 | 1820 | 1876 | yes |  |
| 5x4 | anonymous public owners | full+spl | yes | 3206 | 30 | 3 | - | 1952 | 1880 | yes |  |
| 5x4 | anonymous public owners | full+data | yes | 3236 | 23 | 3 | - | 2218 | 2266 | yes |  |
| 5x4 | anonymous public owners | full+reply | yes | 3131 | 23 | 3 | - | 2113 | 2167 | yes |  |
| 5x4 | anonymous public owners | full+2tree | yes | 2844 | 23 | 3 | - | 1825 | 1880 | yes |  |
| 5x4 | anonymous public owners | full+4credential-shared | yes | 2914 | 25 | 3 | - | 1829 | 1880 | yes |  |
| 5x4 | anonymous public owners | full+4credential-disjoint | yes | 3010 | 28 | 3 | - | 1829 | 1880 | yes |  |
| 5x4 | confidential entry | min | yes | 3016 | 12 | 1 | - | 2499 | 2591 | yes |  |
| 5x4 | confidential entry | full | yes | 3606 | 23 | 3 | 5 | 2588 | 2636 | yes |  |
| 5x4 | confidential entry | full+spl | yes | 3974 | 30 | 3 | - | 2720 | 2640 | yes |  |
| 5x4 | confidential entry | full+data | yes | 4004 | 23 | 3 | - | 2986 | 3026 | yes |  |
| 5x4 | confidential entry | full+reply | yes | 3606 | 23 | 3 | - | 2588 | 2636 | yes |  |
| 5x4 | confidential entry | full+2tree | yes | 3612 | 23 | 3 | - | 2593 | 2640 | yes |  |
| 5x4 | confidential entry | full+4credential-shared | yes | 3682 | 25 | 3 | - | 2597 | 2640 | yes |  |
| 5x4 | confidential entry | full+4credential-disjoint | yes | 3778 | 28 | 3 | - | 2597 | 2640 | yes |  |
| 5x4 | anonymous entry | min | yes | 3279 | 12 | 1 | - | 2763 | 2854 | yes |  |
| 5x4 | anonymous entry | full | yes | 3749 | 19 | 2 | 3 | 2924 | 2981 | yes |  |
| 5x4 | anonymous entry | full+spl | yes | 4117 | 26 | 2 | - | 3056 | 2985 | no | 21 B |
| 5x4 | anonymous entry | full+data | yes | 4147 | 19 | 2 | - | 3322 | 3371 | no | 51 B |
| 5x4 | anonymous entry | full+reply | yes | 4042 | 19 | 2 | - | 3217 | 3272 | yes |  |
| 5x4 | anonymous entry | full+2tree | yes | 3755 | 19 | 2 | - | 2929 | 2985 | yes |  |
| 5x4 | anonymous entry | full+4credential-shared | yes | 3825 | 21 | 2 | - | 2933 | 2985 | yes |  |
| 5x4 | anonymous entry | full+4credential-disjoint | yes | 3921 | 24 | 2 | - | 2933 | 2985 | yes |  |
| 5x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x16 | confidential signer | min | yes | 4549 | 11 | 1 | - | 4065 | 4586 | no | 453 B |
| 4x16 | confidential signer | full | yes | 5139 | 22 | 3 | none | 4154 | 4631 | no | 1043 B |
| 4x16 | confidential signer | full+spl | yes | 5507 | 29 | 3 | - | 4286 | 4635 | no | 1411 B |
| 4x16 | confidential signer | full+data | yes | 6725 | 22 | 3 | - | 5740 | 6185 | no | 2629 B |
| 4x16 | confidential signer | full+reply | yes | 5139 | 22 | 3 | - | 4154 | 4631 | no | 1043 B |
| 4x16 | confidential signer | full+2tree | yes | 5145 | 22 | 3 | - | 4159 | 4635 | no | 1049 B |
| 4x16 | confidential signer | full+4credential-shared | yes | 5215 | 24 | 3 | - | 4163 | 4635 | no | 1119 B |
| 4x16 | confidential signer | full+4credential-disjoint | yes | 5311 | 27 | 3 | - | 4163 | 4635 | no | 1215 B |
| 4x16 | confidential in-proof | min | yes | 4644 | 11 | 1 | - | 4161 | 4683 | no | 548 B |
| 4x16 | confidential in-proof | full | yes | 5138 | 21 | 2 | none | 4250 | 4728 | no | 1042 B |
| 4x16 | confidential in-proof | full+spl | yes | 5506 | 28 | 2 | - | 4382 | 4732 | no | 1410 B |
| 4x16 | confidential in-proof | full+data | yes | 6724 | 21 | 2 | - | 5836 | 6282 | no | 2628 B |
| 4x16 | confidential in-proof | full+reply | yes | 5138 | 21 | 2 | - | 4250 | 4728 | no | 1042 B |
| 4x16 | confidential in-proof | full+2tree | yes | 5144 | 21 | 2 | - | 4255 | 4732 | no | 1048 B |
| 4x16 | confidential in-proof | full+4credential-shared | yes | 5214 | 23 | 2 | - | 4259 | 4732 | no | 1118 B |
| 4x16 | confidential in-proof | full+4credential-disjoint | yes | 5310 | 26 | 2 | - | 4259 | 4732 | no | 1214 B |
| 4x16 | anonymous hidden | min | yes | 5164 | 11 | 1 | - | 4681 | 5233 | no | 1068 B |
| 4x16 | anonymous hidden | full | yes | 5634 | 18 | 2 | none | 4842 | 5360 | no | 1538 B |
| 4x16 | anonymous hidden | full+spl | yes | 6002 | 25 | 2 | - | 4974 | 5364 | no | 1906 B |
| 4x16 | anonymous hidden | full+data | yes | 7220 | 18 | 2 | - | 6428 | 6914 | no | 3124 B |
| 4x16 | anonymous hidden | full+reply | yes | 7091 | 18 | 2 | - | 6299 | 6815 | no | 2995 B |
| 4x16 | anonymous hidden | full+2tree | yes | 5640 | 18 | 2 | - | 4847 | 5364 | no | 1544 B |
| 4x16 | anonymous hidden | full+4credential-shared | yes | 5710 | 20 | 2 | - | 4851 | 5364 | no | 1614 B |
| 4x16 | anonymous hidden | full+4credential-disjoint | yes | 5806 | 23 | 2 | - | 4851 | 5364 | no | 1710 B |
| 4x16 | anonymous public owners | min | yes | 5101 | 11 | 1 | - | 4617 | 5136 | no | 1005 B |
| 4x16 | anonymous public owners | full | yes | 5763 | 22 | 3 | none | 4778 | 5263 | no | 1667 B |
| 4x16 | anonymous public owners | full+spl | yes | 6131 | 29 | 3 | - | 4910 | 5267 | no | 2035 B |
| 4x16 | anonymous public owners | full+data | yes | 7349 | 22 | 3 | - | 6364 | 6817 | no | 3253 B |
| 4x16 | anonymous public owners | full+reply | yes | 7220 | 22 | 3 | - | 6235 | 6718 | no | 3124 B |
| 4x16 | anonymous public owners | full+2tree | yes | 5769 | 22 | 3 | - | 4783 | 5267 | no | 1673 B |
| 4x16 | anonymous public owners | full+4credential-shared | yes | 5839 | 24 | 3 | - | 4787 | 5267 | no | 1743 B |
| 4x16 | anonymous public owners | full+4credential-disjoint | yes | 5935 | 27 | 3 | - | 4787 | 5267 | no | 1839 B |
| 4x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x8 | confidential signer | min | yes | 2876 | 12 | 1 | - | 2359 | 2595 | yes |  |
| 5x8 | confidential signer | full | yes | 3466 | 23 | 3 | 5 | 2448 | 2640 | yes |  |
| 5x8 | confidential signer | full+spl | yes | 3834 | 30 | 3 | - | 2580 | 2644 | yes |  |
| 5x8 | confidential signer | full+data | yes | 4260 | 23 | 3 | - | 3242 | 3418 | no | 164 B |
| 5x8 | confidential signer | full+reply | yes | 3466 | 23 | 3 | - | 2448 | 2640 | yes |  |
| 5x8 | confidential signer | full+2tree | yes | 3472 | 23 | 3 | - | 2453 | 2644 | yes |  |
| 5x8 | confidential signer | full+4credential-shared | yes | 3542 | 25 | 3 | - | 2457 | 2644 | yes |  |
| 5x8 | confidential signer | full+4credential-disjoint | yes | 3638 | 28 | 3 | - | 2457 | 2644 | yes |  |
| 5x8 | confidential in-proof | min | yes | 2971 | 12 | 1 | - | 2455 | 2692 | yes |  |
| 5x8 | confidential in-proof | full | yes | 3465 | 22 | 2 | 5 | 2544 | 2737 | yes |  |
| 5x8 | confidential in-proof | full+spl | yes | 3833 | 29 | 2 | - | 2676 | 2741 | yes |  |
| 5x8 | confidential in-proof | full+data | yes | 4259 | 22 | 2 | - | 3338 | 3515 | no | 163 B |
| 5x8 | confidential in-proof | full+reply | yes | 3465 | 22 | 2 | - | 2544 | 2737 | yes |  |
| 5x8 | confidential in-proof | full+2tree | yes | 3471 | 22 | 2 | - | 2549 | 2741 | yes |  |
| 5x8 | confidential in-proof | full+4credential-shared | yes | 3541 | 24 | 2 | - | 2553 | 2741 | yes |  |
| 5x8 | confidential in-proof | full+4credential-disjoint | yes | 3637 | 27 | 2 | - | 2553 | 2741 | yes |  |
| 5x8 | anonymous hidden | min | yes | 3235 | 12 | 1 | - | 2719 | 2986 | yes |  |
| 5x8 | anonymous hidden | full | yes | 3705 | 19 | 2 | 4 | 2880 | 3113 | yes |  |
| 5x8 | anonymous hidden | full+spl | yes | 4073 | 26 | 2 | - | 3012 | 3117 | yes |  |
| 5x8 | anonymous hidden | full+data | yes | 4499 | 19 | 2 | - | 3674 | 3891 | no | 403 B |
| 5x8 | anonymous hidden | full+reply | yes | 4386 | 19 | 2 | - | 3561 | 3792 | no | 290 B |
| 5x8 | anonymous hidden | full+2tree | yes | 3711 | 19 | 2 | - | 2885 | 3117 | yes |  |
| 5x8 | anonymous hidden | full+4credential-shared | yes | 3781 | 21 | 2 | - | 2889 | 3117 | yes |  |
| 5x8 | anonymous hidden | full+4credential-disjoint | yes | 3877 | 24 | 2 | - | 2889 | 3117 | yes |  |
| 5x8 | anonymous public owners | min | yes | 3172 | 12 | 1 | - | 2655 | 2889 | yes |  |
| 5x8 | anonymous public owners | full | yes | 3834 | 23 | 3 | 3 | 2816 | 3016 | yes |  |
| 5x8 | anonymous public owners | full+spl | yes | 4202 | 30 | 3 | - | 2948 | 3020 | no | 106 B |
| 5x8 | anonymous public owners | full+data | yes | 4628 | 23 | 3 | - | 3610 | 3794 | no | 532 B |
| 5x8 | anonymous public owners | full+reply | yes | 4515 | 23 | 3 | - | 3497 | 3695 | no | 419 B |
| 5x8 | anonymous public owners | full+2tree | yes | 3840 | 23 | 3 | - | 2821 | 3020 | yes |  |
| 5x8 | anonymous public owners | full+4credential-shared | yes | 3910 | 25 | 3 | - | 2825 | 3020 | yes |  |
| 5x8 | anonymous public owners | full+4credential-disjoint | yes | 4006 | 28 | 3 | - | 2825 | 3020 | yes |  |
| 5x8 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 5x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x2 | confidential signer | min | yes | 1639 | 13 | 1 | - | 1089 | 1110 | yes |  |
| 6x2 | confidential signer | full | yes | 2229 | 24 | 3 | 6 | 1178 | 1155 | yes |  |
| 6x2 | confidential signer | full+spl | yes | 2597 | 31 | 3 | - | 1310 | 1159 | yes |  |
| 6x2 | confidential signer | full+data | yes | 2429 | 24 | 3 | - | 1378 | 1351 | yes |  |
| 6x2 | confidential signer | full+reply | yes | 2229 | 24 | 3 | - | 1178 | 1155 | yes |  |
| 6x2 | confidential signer | full+2tree | yes | 2235 | 24 | 3 | - | 1183 | 1159 | yes |  |
| 6x2 | confidential signer | full+4credential-shared | yes | 2305 | 26 | 3 | - | 1187 | 1159 | yes |  |
| 6x2 | confidential signer | full+4credential-disjoint | yes | 2401 | 29 | 3 | - | 1187 | 1159 | yes |  |
| 6x2 | confidential in-proof | min | yes | 1734 | 13 | 1 | - | 1185 | 1207 | yes |  |
| 6x2 | confidential in-proof | full | yes | 2228 | 23 | 2 | 6 | 1274 | 1252 | yes |  |
| 6x2 | confidential in-proof | full+spl | yes | 2596 | 30 | 2 | - | 1406 | 1256 | yes |  |
| 6x2 | confidential in-proof | full+data | yes | 2428 | 23 | 2 | - | 1474 | 1448 | yes |  |
| 6x2 | confidential in-proof | full+reply | yes | 2228 | 23 | 2 | - | 1274 | 1252 | yes |  |
| 6x2 | confidential in-proof | full+2tree | yes | 2234 | 23 | 2 | - | 1279 | 1256 | yes |  |
| 6x2 | confidential in-proof | full+4credential-shared | yes | 2304 | 25 | 2 | - | 1283 | 1256 | yes |  |
| 6x2 | confidential in-proof | full+4credential-disjoint | yes | 2400 | 28 | 2 | - | 1283 | 1256 | yes |  |
| 6x2 | anonymous hidden | min | yes | 1806 | 13 | 1 | - | 1257 | 1309 | yes |  |
| 6x2 | anonymous hidden | full | yes | 2276 | 20 | 2 | 6 | 1418 | 1436 | yes |  |
| 6x2 | anonymous hidden | full+spl | yes | 2644 | 27 | 2 | - | 1550 | 1440 | yes |  |
| 6x2 | anonymous hidden | full+data | yes | 2476 | 20 | 2 | - | 1618 | 1632 | yes |  |
| 6x2 | anonymous hidden | full+reply | yes | 2375 | 20 | 2 | - | 1517 | 1533 | yes |  |
| 6x2 | anonymous hidden | full+2tree | yes | 2282 | 20 | 2 | - | 1423 | 1440 | yes |  |
| 6x2 | anonymous hidden | full+4credential-shared | yes | 2352 | 22 | 2 | - | 1427 | 1440 | yes |  |
| 6x2 | anonymous hidden | full+4credential-disjoint | yes | 2448 | 25 | 2 | - | 1427 | 1440 | yes |  |
| 6x2 | anonymous public owners | min | yes | 1743 | 13 | 1 | - | 1193 | 1212 | yes |  |
| 6x2 | anonymous public owners | full | yes | 2405 | 24 | 3 | 6 | 1354 | 1339 | yes |  |
| 6x2 | anonymous public owners | full+spl | yes | 2773 | 31 | 3 | - | 1486 | 1343 | yes |  |
| 6x2 | anonymous public owners | full+data | yes | 2605 | 24 | 3 | - | 1554 | 1535 | yes |  |
| 6x2 | anonymous public owners | full+reply | yes | 2504 | 24 | 3 | - | 1453 | 1436 | yes |  |
| 6x2 | anonymous public owners | full+2tree | yes | 2411 | 24 | 3 | - | 1359 | 1343 | yes |  |
| 6x2 | anonymous public owners | full+4credential-shared | yes | 2481 | 26 | 3 | - | 1363 | 1343 | yes |  |
| 6x2 | anonymous public owners | full+4credential-disjoint | yes | 2577 | 29 | 3 | - | 1363 | 1343 | yes |  |
| 6x2 | confidential entry | min | yes | 2847 | 13 | 1 | - | 2297 | 2318 | yes |  |
| 6x2 | confidential entry | full | yes | 3437 | 24 | 3 | 6 | 2386 | 2363 | yes |  |
| 6x2 | confidential entry | full+spl | yes | 3805 | 31 | 3 | - | 2518 | 2367 | yes |  |
| 6x2 | confidential entry | full+data | yes | 3637 | 24 | 3 | - | 2586 | 2559 | yes |  |
| 6x2 | confidential entry | full+reply | yes | 3437 | 24 | 3 | - | 2386 | 2363 | yes |  |
| 6x2 | confidential entry | full+2tree | yes | 3443 | 24 | 3 | - | 2391 | 2367 | yes |  |
| 6x2 | confidential entry | full+4credential-shared | yes | 3513 | 26 | 3 | - | 2395 | 2367 | yes |  |
| 6x2 | confidential entry | full+4credential-disjoint | yes | 3609 | 29 | 3 | - | 2395 | 2367 | yes |  |
| 6x2 | anonymous entry | min | yes | 3046 | 13 | 1 | - | 2497 | 2517 | yes |  |
| 6x2 | anonymous entry | full | yes | 3516 | 20 | 2 | 5 | 2658 | 2644 | yes |  |
| 6x2 | anonymous entry | full+spl | yes | 3884 | 27 | 2 | - | 2790 | 2648 | yes |  |
| 6x2 | anonymous entry | full+data | yes | 3716 | 20 | 2 | - | 2858 | 2840 | yes |  |
| 6x2 | anonymous entry | full+reply | yes | 3615 | 20 | 2 | - | 2757 | 2741 | yes |  |
| 6x2 | anonymous entry | full+2tree | yes | 3522 | 20 | 2 | - | 2663 | 2648 | yes |  |
| 6x2 | anonymous entry | full+4credential-shared | yes | 3592 | 22 | 2 | - | 2667 | 2648 | yes |  |
| 6x2 | anonymous entry | full+4credential-disjoint | yes | 3688 | 25 | 2 | - | 2667 | 2648 | yes |  |
| 6x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x4 | confidential signer | min | yes | 2073 | 13 | 1 | - | 1523 | 1616 | yes |  |
| 6x4 | confidential signer | full | yes | 2663 | 24 | 3 | 6 | 1612 | 1661 | yes |  |
| 6x4 | confidential signer | full+spl | yes | 3031 | 31 | 3 | - | 1744 | 1665 | yes |  |
| 6x4 | confidential signer | full+data | yes | 3061 | 24 | 3 | - | 2010 | 2051 | yes |  |
| 6x4 | confidential signer | full+reply | yes | 2663 | 24 | 3 | - | 1612 | 1661 | yes |  |
| 6x4 | confidential signer | full+2tree | yes | 2669 | 24 | 3 | - | 1617 | 1665 | yes |  |
| 6x4 | confidential signer | full+4credential-shared | yes | 2739 | 26 | 3 | - | 1621 | 1665 | yes |  |
| 6x4 | confidential signer | full+4credential-disjoint | yes | 2835 | 29 | 3 | - | 1621 | 1665 | yes |  |
| 6x4 | confidential in-proof | min | yes | 2168 | 13 | 1 | - | 1619 | 1713 | yes |  |
| 6x4 | confidential in-proof | full | yes | 2662 | 23 | 2 | 6 | 1708 | 1758 | yes |  |
| 6x4 | confidential in-proof | full+spl | yes | 3030 | 30 | 2 | - | 1840 | 1762 | yes |  |
| 6x4 | confidential in-proof | full+data | yes | 3060 | 23 | 2 | - | 2106 | 2148 | yes |  |
| 6x4 | confidential in-proof | full+reply | yes | 2662 | 23 | 2 | - | 1708 | 1758 | yes |  |
| 6x4 | confidential in-proof | full+2tree | yes | 2668 | 23 | 2 | - | 1713 | 1762 | yes |  |
| 6x4 | confidential in-proof | full+4credential-shared | yes | 2738 | 25 | 2 | - | 1717 | 1762 | yes |  |
| 6x4 | confidential in-proof | full+4credential-disjoint | yes | 2834 | 28 | 2 | - | 1717 | 1762 | yes |  |
| 6x4 | anonymous hidden | min | yes | 2304 | 13 | 1 | - | 1755 | 1879 | yes |  |
| 6x4 | anonymous hidden | full | yes | 2774 | 20 | 2 | 6 | 1916 | 2006 | yes |  |
| 6x4 | anonymous hidden | full+spl | yes | 3142 | 27 | 2 | - | 2048 | 2010 | yes |  |
| 6x4 | anonymous hidden | full+data | yes | 3172 | 20 | 2 | - | 2314 | 2396 | yes |  |
| 6x4 | anonymous hidden | full+reply | yes | 3067 | 20 | 2 | - | 2209 | 2297 | yes |  |
| 6x4 | anonymous hidden | full+2tree | yes | 2780 | 20 | 2 | - | 1921 | 2010 | yes |  |
| 6x4 | anonymous hidden | full+4credential-shared | yes | 2850 | 22 | 2 | - | 1925 | 2010 | yes |  |
| 6x4 | anonymous hidden | full+4credential-disjoint | yes | 2946 | 25 | 2 | - | 1925 | 2010 | yes |  |
| 6x4 | anonymous public owners | min | yes | 2241 | 13 | 1 | - | 1691 | 1782 | yes |  |
| 6x4 | anonymous public owners | full | yes | 2903 | 24 | 3 | 6 | 1852 | 1909 | yes |  |
| 6x4 | anonymous public owners | full+spl | yes | 3271 | 31 | 3 | - | 1984 | 1913 | yes |  |
| 6x4 | anonymous public owners | full+data | yes | 3301 | 24 | 3 | - | 2250 | 2299 | yes |  |
| 6x4 | anonymous public owners | full+reply | yes | 3196 | 24 | 3 | - | 2145 | 2200 | yes |  |
| 6x4 | anonymous public owners | full+2tree | yes | 2909 | 24 | 3 | - | 1857 | 1913 | yes |  |
| 6x4 | anonymous public owners | full+4credential-shared | yes | 2979 | 26 | 3 | - | 1861 | 1913 | yes |  |
| 6x4 | anonymous public owners | full+4credential-disjoint | yes | 3075 | 29 | 3 | - | 1861 | 1913 | yes |  |
| 6x4 | confidential entry | min | yes | 3281 | 13 | 1 | - | 2731 | 2824 | yes |  |
| 6x4 | confidential entry | full | yes | 3871 | 24 | 3 | 3 | 2820 | 2869 | yes |  |
| 6x4 | confidential entry | full+spl | yes | 4239 | 31 | 3 | - | 2952 | 2873 | no | 143 B |
| 6x4 | confidential entry | full+data | yes | 4269 | 24 | 3 | - | 3218 | 3259 | no | 173 B |
| 6x4 | confidential entry | full+reply | yes | 3871 | 24 | 3 | - | 2820 | 2869 | yes |  |
| 6x4 | confidential entry | full+2tree | yes | 3877 | 24 | 3 | - | 2825 | 2873 | yes |  |
| 6x4 | confidential entry | full+4credential-shared | yes | 3947 | 26 | 3 | - | 2829 | 2873 | yes |  |
| 6x4 | confidential entry | full+4credential-disjoint | yes | 4043 | 29 | 3 | - | 2829 | 2873 | yes |  |
| 6x4 | anonymous entry | min | yes | 3544 | 13 | 1 | - | 2995 | 3087 | yes |  |
| 6x4 | anonymous entry | full | yes | 4014 | 20 | 2 | 0 | 3156 | 3214 | yes |  |
| 6x4 | anonymous entry | full+spl | yes | 4382 | 27 | 2 | - | 3288 | 3218 | no | 286 B |
| 6x4 | anonymous entry | full+data | yes | 4412 | 20 | 2 | - | 3554 | 3604 | no | 316 B |
| 6x4 | anonymous entry | full+reply | yes | 4307 | 20 | 2 | - | 3449 | 3505 | no | 211 B |
| 6x4 | anonymous entry | full+2tree | yes | 4020 | 20 | 2 | - | 3161 | 3218 | yes |  |
| 6x4 | anonymous entry | full+4credential-shared | yes | 4090 | 22 | 2 | - | 3165 | 3218 | yes |  |
| 6x4 | anonymous entry | full+4credential-disjoint | yes | 4186 | 25 | 2 | - | 3165 | 3218 | no | 90 B |
| 6x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x16 | confidential signer | min | yes | 4614 | 12 | 1 | - | 4097 | 4619 | no | 518 B |
| 5x16 | confidential signer | full | yes | 5204 | 23 | 3 | none | 4186 | 4664 | no | 1108 B |
| 5x16 | confidential signer | full+spl | yes | 5572 | 30 | 3 | - | 4318 | 4668 | no | 1476 B |
| 5x16 | confidential signer | full+data | yes | 6790 | 23 | 3 | - | 5772 | 6218 | no | 2694 B |
| 5x16 | confidential signer | full+reply | yes | 5204 | 23 | 3 | - | 4186 | 4664 | no | 1108 B |
| 5x16 | confidential signer | full+2tree | yes | 5210 | 23 | 3 | - | 4191 | 4668 | no | 1114 B |
| 5x16 | confidential signer | full+4credential-shared | yes | 5280 | 25 | 3 | - | 4195 | 4668 | no | 1184 B |
| 5x16 | confidential signer | full+4credential-disjoint | yes | 5376 | 28 | 3 | - | 4195 | 4668 | no | 1280 B |
| 5x16 | confidential in-proof | min | yes | 4709 | 12 | 1 | - | 4193 | 4716 | no | 613 B |
| 5x16 | confidential in-proof | full | yes | 5203 | 22 | 2 | none | 4282 | 4761 | no | 1107 B |
| 5x16 | confidential in-proof | full+spl | yes | 5571 | 29 | 2 | - | 4414 | 4765 | no | 1475 B |
| 5x16 | confidential in-proof | full+data | yes | 6789 | 22 | 2 | - | 5868 | 6315 | no | 2693 B |
| 5x16 | confidential in-proof | full+reply | yes | 5203 | 22 | 2 | - | 4282 | 4761 | no | 1107 B |
| 5x16 | confidential in-proof | full+2tree | yes | 5209 | 22 | 2 | - | 4287 | 4765 | no | 1113 B |
| 5x16 | confidential in-proof | full+4credential-shared | yes | 5279 | 24 | 2 | - | 4291 | 4765 | no | 1183 B |
| 5x16 | confidential in-proof | full+4credential-disjoint | yes | 5375 | 27 | 2 | - | 4291 | 4765 | no | 1279 B |
| 5x16 | anonymous hidden | min | yes | 5229 | 12 | 1 | - | 4713 | 5266 | no | 1133 B |
| 5x16 | anonymous hidden | full | yes | 5699 | 19 | 2 | none | 4874 | 5393 | no | 1603 B |
| 5x16 | anonymous hidden | full+spl | yes | 6067 | 26 | 2 | - | 5006 | 5397 | no | 1971 B |
| 5x16 | anonymous hidden | full+data | yes | 7285 | 19 | 2 | - | 6460 | 6947 | no | 3189 B |
| 5x16 | anonymous hidden | full+reply | yes | 7156 | 19 | 2 | - | 6331 | 6848 | no | 3060 B |
| 5x16 | anonymous hidden | full+2tree | yes | 5705 | 19 | 2 | - | 4879 | 5397 | no | 1609 B |
| 5x16 | anonymous hidden | full+4credential-shared | yes | 5775 | 21 | 2 | - | 4883 | 5397 | no | 1679 B |
| 5x16 | anonymous hidden | full+4credential-disjoint | yes | 5871 | 24 | 2 | - | 4883 | 5397 | no | 1775 B |
| 5x16 | anonymous public owners | min | yes | 5166 | 12 | 1 | - | 4649 | 5169 | no | 1070 B |
| 5x16 | anonymous public owners | full | yes | 5828 | 23 | 3 | none | 4810 | 5296 | no | 1732 B |
| 5x16 | anonymous public owners | full+spl | yes | 6196 | 30 | 3 | - | 4942 | 5300 | no | 2100 B |
| 5x16 | anonymous public owners | full+data | yes | 7414 | 23 | 3 | - | 6396 | 6850 | no | 3318 B |
| 5x16 | anonymous public owners | full+reply | yes | 7285 | 23 | 3 | - | 6267 | 6751 | no | 3189 B |
| 5x16 | anonymous public owners | full+2tree | yes | 5834 | 23 | 3 | - | 4815 | 5300 | no | 1738 B |
| 5x16 | anonymous public owners | full+4credential-shared | yes | 5904 | 25 | 3 | - | 4819 | 5300 | no | 1808 B |
| 5x16 | anonymous public owners | full+4credential-disjoint | yes | 6000 | 28 | 3 | - | 4819 | 5300 | no | 1904 B |
| 5x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x8 | confidential signer | min | yes | 2941 | 13 | 1 | - | 2391 | 2628 | yes |  |
| 6x8 | confidential signer | full | yes | 3531 | 24 | 3 | 6 | 2480 | 2673 | yes |  |
| 6x8 | confidential signer | full+spl | yes | 3899 | 31 | 3 | - | 2612 | 2677 | yes |  |
| 6x8 | confidential signer | full+data | yes | 4325 | 24 | 3 | - | 3274 | 3451 | no | 229 B |
| 6x8 | confidential signer | full+reply | yes | 3531 | 24 | 3 | - | 2480 | 2673 | yes |  |
| 6x8 | confidential signer | full+2tree | yes | 3537 | 24 | 3 | - | 2485 | 2677 | yes |  |
| 6x8 | confidential signer | full+4credential-shared | yes | 3607 | 26 | 3 | - | 2489 | 2677 | yes |  |
| 6x8 | confidential signer | full+4credential-disjoint | yes | 3703 | 29 | 3 | - | 2489 | 2677 | yes |  |
| 6x8 | confidential in-proof | min | yes | 3036 | 13 | 1 | - | 2487 | 2725 | yes |  |
| 6x8 | confidential in-proof | full | yes | 3530 | 23 | 2 | 5 | 2576 | 2770 | yes |  |
| 6x8 | confidential in-proof | full+spl | yes | 3898 | 30 | 2 | - | 2708 | 2774 | yes |  |
| 6x8 | confidential in-proof | full+data | yes | 4324 | 23 | 2 | - | 3370 | 3548 | no | 228 B |
| 6x8 | confidential in-proof | full+reply | yes | 3530 | 23 | 2 | - | 2576 | 2770 | yes |  |
| 6x8 | confidential in-proof | full+2tree | yes | 3536 | 23 | 2 | - | 2581 | 2774 | yes |  |
| 6x8 | confidential in-proof | full+4credential-shared | yes | 3606 | 25 | 2 | - | 2585 | 2774 | yes |  |
| 6x8 | confidential in-proof | full+4credential-disjoint | yes | 3702 | 28 | 2 | - | 2585 | 2774 | yes |  |
| 6x8 | anonymous hidden | min | yes | 3300 | 13 | 1 | - | 2751 | 3019 | yes |  |
| 6x8 | anonymous hidden | full | yes | 3770 | 20 | 2 | 3 | 2912 | 3146 | yes |  |
| 6x8 | anonymous hidden | full+spl | yes | 4138 | 27 | 2 | - | 3044 | 3150 | no | 42 B |
| 6x8 | anonymous hidden | full+data | yes | 4564 | 20 | 2 | - | 3706 | 3924 | no | 468 B |
| 6x8 | anonymous hidden | full+reply | yes | 4451 | 20 | 2 | - | 3593 | 3825 | no | 355 B |
| 6x8 | anonymous hidden | full+2tree | yes | 3776 | 20 | 2 | - | 2917 | 3150 | yes |  |
| 6x8 | anonymous hidden | full+4credential-shared | yes | 3846 | 22 | 2 | - | 2921 | 3150 | yes |  |
| 6x8 | anonymous hidden | full+4credential-disjoint | yes | 3942 | 25 | 2 | - | 2921 | 3150 | yes |  |
| 6x8 | anonymous public owners | min | yes | 3237 | 13 | 1 | - | 2687 | 2922 | yes |  |
| 6x8 | anonymous public owners | full | yes | 3899 | 24 | 3 | 3 | 2848 | 3049 | yes |  |
| 6x8 | anonymous public owners | full+spl | yes | 4267 | 31 | 3 | - | 2980 | 3053 | no | 171 B |
| 6x8 | anonymous public owners | full+data | yes | 4693 | 24 | 3 | - | 3642 | 3827 | no | 597 B |
| 6x8 | anonymous public owners | full+reply | yes | 4580 | 24 | 3 | - | 3529 | 3728 | no | 484 B |
| 6x8 | anonymous public owners | full+2tree | yes | 3905 | 24 | 3 | - | 2853 | 3053 | yes |  |
| 6x8 | anonymous public owners | full+4credential-shared | yes | 3975 | 26 | 3 | - | 2857 | 3053 | yes |  |
| 6x8 | anonymous public owners | full+4credential-disjoint | yes | 4071 | 29 | 3 | - | 2857 | 3053 | yes |  |
| 6x8 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 6x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x2 | confidential signer | min | yes | 1769 | 15 | 1 | - | 1153 | 1176 | yes |  |
| 8x2 | confidential signer | full | yes | 2359 | 26 | 3 | 8 | 1242 | 1221 | yes |  |
| 8x2 | confidential signer | full+spl | yes | 2727 | 33 | 3 | - | 1374 | 1225 | yes |  |
| 8x2 | confidential signer | full+data | yes | 2559 | 26 | 3 | - | 1442 | 1417 | yes |  |
| 8x2 | confidential signer | full+reply | yes | 2359 | 26 | 3 | - | 1242 | 1221 | yes |  |
| 8x2 | confidential signer | full+2tree | yes | 2365 | 26 | 3 | - | 1247 | 1225 | yes |  |
| 8x2 | confidential signer | full+4credential-shared | yes | 2435 | 28 | 3 | - | 1251 | 1225 | yes |  |
| 8x2 | confidential signer | full+4credential-disjoint | yes | 2531 | 31 | 3 | - | 1251 | 1225 | yes |  |
| 8x2 | confidential in-proof | min | yes | 1864 | 15 | 1 | - | 1249 | 1273 | yes |  |
| 8x2 | confidential in-proof | full | yes | 2358 | 25 | 2 | 8 | 1338 | 1318 | yes |  |
| 8x2 | confidential in-proof | full+spl | yes | 2726 | 32 | 2 | - | 1470 | 1322 | yes |  |
| 8x2 | confidential in-proof | full+data | yes | 2558 | 25 | 2 | - | 1538 | 1514 | yes |  |
| 8x2 | confidential in-proof | full+reply | yes | 2358 | 25 | 2 | - | 1338 | 1318 | yes |  |
| 8x2 | confidential in-proof | full+2tree | yes | 2364 | 25 | 2 | - | 1343 | 1322 | yes |  |
| 8x2 | confidential in-proof | full+4credential-shared | yes | 2434 | 27 | 2 | - | 1347 | 1322 | yes |  |
| 8x2 | confidential in-proof | full+4credential-disjoint | yes | 2530 | 30 | 2 | - | 1347 | 1322 | yes |  |
| 8x2 | anonymous hidden | min | yes | 1936 | 15 | 1 | - | 1321 | 1375 | yes |  |
| 8x2 | anonymous hidden | full | yes | 2406 | 22 | 2 | 8 | 1482 | 1502 | yes |  |
| 8x2 | anonymous hidden | full+spl | yes | 2774 | 29 | 2 | - | 1614 | 1506 | yes |  |
| 8x2 | anonymous hidden | full+data | yes | 2606 | 22 | 2 | - | 1682 | 1698 | yes |  |
| 8x2 | anonymous hidden | full+reply | yes | 2505 | 22 | 2 | - | 1581 | 1599 | yes |  |
| 8x2 | anonymous hidden | full+2tree | yes | 2412 | 22 | 2 | - | 1487 | 1506 | yes |  |
| 8x2 | anonymous hidden | full+4credential-shared | yes | 2482 | 24 | 2 | - | 1491 | 1506 | yes |  |
| 8x2 | anonymous hidden | full+4credential-disjoint | yes | 2578 | 27 | 2 | - | 1491 | 1506 | yes |  |
| 8x2 | anonymous public owners | min | yes | 1873 | 15 | 1 | - | 1257 | 1278 | yes |  |
| 8x2 | anonymous public owners | full | yes | 2535 | 26 | 3 | 8 | 1418 | 1405 | yes |  |
| 8x2 | anonymous public owners | full+spl | yes | 2903 | 33 | 3 | - | 1550 | 1409 | yes |  |
| 8x2 | anonymous public owners | full+data | yes | 2735 | 26 | 3 | - | 1618 | 1601 | yes |  |
| 8x2 | anonymous public owners | full+reply | yes | 2634 | 26 | 3 | - | 1517 | 1502 | yes |  |
| 8x2 | anonymous public owners | full+2tree | yes | 2541 | 26 | 3 | - | 1423 | 1409 | yes |  |
| 8x2 | anonymous public owners | full+4credential-shared | yes | 2611 | 28 | 3 | - | 1427 | 1409 | yes |  |
| 8x2 | anonymous public owners | full+4credential-disjoint | yes | 2707 | 31 | 3 | - | 1427 | 1409 | yes |  |
| 8x2 | confidential entry | min | yes | 3377 | 15 | 1 | - | 2761 | 2784 | yes |  |
| 8x2 | confidential entry | full | yes | 3967 | 26 | 3 | 2 | 2850 | 2829 | yes |  |
| 8x2 | confidential entry | full+spl | yes | 4335 | 33 | 3 | - | 2982 | 2833 | no | 239 B |
| 8x2 | confidential entry | full+data | yes | 4167 | 26 | 3 | - | 3050 | 3025 | no | 71 B |
| 8x2 | confidential entry | full+reply | yes | 3967 | 26 | 3 | - | 2850 | 2829 | yes |  |
| 8x2 | confidential entry | full+2tree | yes | 3973 | 26 | 3 | - | 2855 | 2833 | yes |  |
| 8x2 | confidential entry | full+4credential-shared | yes | 4043 | 28 | 3 | - | 2859 | 2833 | yes |  |
| 8x2 | confidential entry | full+4credential-disjoint | yes | 4139 | 31 | 3 | - | 2859 | 2833 | no | 43 B |
| 8x2 | anonymous entry | min | yes | 3576 | 15 | 1 | - | 2961 | 2983 | yes |  |
| 8x2 | anonymous entry | full | yes | 4046 | 22 | 2 | 0 | 3122 | 3110 | yes |  |
| 8x2 | anonymous entry | full+spl | yes | 4414 | 29 | 2 | - | 3254 | 3114 | no | 318 B |
| 8x2 | anonymous entry | full+data | yes | 4246 | 22 | 2 | - | 3322 | 3306 | no | 150 B |
| 8x2 | anonymous entry | full+reply | yes | 4145 | 22 | 2 | - | 3221 | 3207 | no | 49 B |
| 8x2 | anonymous entry | full+2tree | yes | 4052 | 22 | 2 | - | 3127 | 3114 | yes |  |
| 8x2 | anonymous entry | full+4credential-shared | yes | 4122 | 24 | 2 | - | 3131 | 3114 | no | 26 B |
| 8x2 | anonymous entry | full+4credential-disjoint | yes | 4218 | 27 | 2 | - | 3131 | 3114 | no | 122 B |
| 8x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x4 | confidential signer | min | yes | 2203 | 15 | 1 | - | 1587 | 1682 | yes |  |
| 8x4 | confidential signer | full | yes | 2793 | 26 | 3 | 8 | 1676 | 1727 | yes |  |
| 8x4 | confidential signer | full+spl | yes | 3161 | 33 | 3 | - | 1808 | 1731 | yes |  |
| 8x4 | confidential signer | full+data | yes | 3191 | 26 | 3 | - | 2074 | 2117 | yes |  |
| 8x4 | confidential signer | full+reply | yes | 2793 | 26 | 3 | - | 1676 | 1727 | yes |  |
| 8x4 | confidential signer | full+2tree | yes | 2799 | 26 | 3 | - | 1681 | 1731 | yes |  |
| 8x4 | confidential signer | full+4credential-shared | yes | 2869 | 28 | 3 | - | 1685 | 1731 | yes |  |
| 8x4 | confidential signer | full+4credential-disjoint | yes | 2965 | 31 | 3 | - | 1685 | 1731 | yes |  |
| 8x4 | confidential in-proof | min | yes | 2298 | 15 | 1 | - | 1683 | 1779 | yes |  |
| 8x4 | confidential in-proof | full | yes | 2792 | 25 | 2 | 8 | 1772 | 1824 | yes |  |
| 8x4 | confidential in-proof | full+spl | yes | 3160 | 32 | 2 | - | 1904 | 1828 | yes |  |
| 8x4 | confidential in-proof | full+data | yes | 3190 | 25 | 2 | - | 2170 | 2214 | yes |  |
| 8x4 | confidential in-proof | full+reply | yes | 2792 | 25 | 2 | - | 1772 | 1824 | yes |  |
| 8x4 | confidential in-proof | full+2tree | yes | 2798 | 25 | 2 | - | 1777 | 1828 | yes |  |
| 8x4 | confidential in-proof | full+4credential-shared | yes | 2868 | 27 | 2 | - | 1781 | 1828 | yes |  |
| 8x4 | confidential in-proof | full+4credential-disjoint | yes | 2964 | 30 | 2 | - | 1781 | 1828 | yes |  |
| 8x4 | anonymous hidden | min | yes | 2434 | 15 | 1 | - | 1819 | 1945 | yes |  |
| 8x4 | anonymous hidden | full | yes | 2904 | 22 | 2 | 8 | 1980 | 2072 | yes |  |
| 8x4 | anonymous hidden | full+spl | yes | 3272 | 29 | 2 | - | 2112 | 2076 | yes |  |
| 8x4 | anonymous hidden | full+data | yes | 3302 | 22 | 2 | - | 2378 | 2462 | yes |  |
| 8x4 | anonymous hidden | full+reply | yes | 3197 | 22 | 2 | - | 2273 | 2363 | yes |  |
| 8x4 | anonymous hidden | full+2tree | yes | 2910 | 22 | 2 | - | 1985 | 2076 | yes |  |
| 8x4 | anonymous hidden | full+4credential-shared | yes | 2980 | 24 | 2 | - | 1989 | 2076 | yes |  |
| 8x4 | anonymous hidden | full+4credential-disjoint | yes | 3076 | 27 | 2 | - | 1989 | 2076 | yes |  |
| 8x4 | anonymous public owners | min | yes | 2371 | 15 | 1 | - | 1755 | 1848 | yes |  |
| 8x4 | anonymous public owners | full | yes | 3033 | 26 | 3 | 8 | 1916 | 1975 | yes |  |
| 8x4 | anonymous public owners | full+spl | yes | 3401 | 33 | 3 | - | 2048 | 1979 | yes |  |
| 8x4 | anonymous public owners | full+data | yes | 3431 | 26 | 3 | - | 2314 | 2365 | yes |  |
| 8x4 | anonymous public owners | full+reply | yes | 3326 | 26 | 3 | - | 2209 | 2266 | yes |  |
| 8x4 | anonymous public owners | full+2tree | yes | 3039 | 26 | 3 | - | 1921 | 1979 | yes |  |
| 8x4 | anonymous public owners | full+4credential-shared | yes | 3109 | 28 | 3 | - | 1925 | 1979 | yes |  |
| 8x4 | anonymous public owners | full+4credential-disjoint | yes | 3205 | 31 | 3 | - | 1925 | 1979 | yes |  |
| 8x4 | confidential entry | min | yes | 3811 | 15 | 1 | - | 3195 | 3290 | yes |  |
| 8x4 | confidential entry | full | yes | 4401 | 26 | 3 | none | 3284 | 3335 | no | 305 B |
| 8x4 | confidential entry | full+spl | yes | 4769 | 33 | 3 | - | 3416 | 3339 | no | 673 B |
| 8x4 | confidential entry | full+data | yes | 4799 | 26 | 3 | - | 3682 | 3725 | no | 703 B |
| 8x4 | confidential entry | full+reply | yes | 4401 | 26 | 3 | - | 3284 | 3335 | no | 305 B |
| 8x4 | confidential entry | full+2tree | yes | 4407 | 26 | 3 | - | 3289 | 3339 | no | 311 B |
| 8x4 | confidential entry | full+4credential-shared | yes | 4477 | 28 | 3 | - | 3293 | 3339 | no | 381 B |
| 8x4 | confidential entry | full+4credential-disjoint | yes | 4573 | 31 | 3 | - | 3293 | 3339 | no | 477 B |
| 8x4 | anonymous entry | min | yes | 4074 | 15 | 1 | - | 3459 | 3553 | yes |  |
| 8x4 | anonymous entry | full | yes | 4544 | 22 | 2 | none | 3620 | 3680 | no | 448 B |
| 8x4 | anonymous entry | full+spl | yes | 4912 | 29 | 2 | - | 3752 | 3684 | no | 816 B |
| 8x4 | anonymous entry | full+data | yes | 4942 | 22 | 2 | - | 4018 | 4070 | no | 846 B |
| 8x4 | anonymous entry | full+reply | yes | 4837 | 22 | 2 | - | 3913 | 3971 | no | 741 B |
| 8x4 | anonymous entry | full+2tree | yes | 4550 | 22 | 2 | - | 3625 | 3684 | no | 454 B |
| 8x4 | anonymous entry | full+4credential-shared | yes | 4620 | 24 | 2 | - | 3629 | 3684 | no | 524 B |
| 8x4 | anonymous entry | full+4credential-disjoint | yes | 4716 | 27 | 2 | - | 3629 | 3684 | no | 620 B |
| 8x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x8 | confidential signer | min | yes | 3071 | 15 | 1 | - | 2455 | 2694 | yes |  |
| 8x8 | confidential signer | full | yes | 3661 | 26 | 3 | 5 | 2544 | 2739 | yes |  |
| 8x8 | confidential signer | full+spl | yes | 4029 | 33 | 3 | - | 2676 | 2743 | yes |  |
| 8x8 | confidential signer | full+data | yes | 4455 | 26 | 3 | - | 3338 | 3517 | no | 359 B |
| 8x8 | confidential signer | full+reply | yes | 3661 | 26 | 3 | - | 2544 | 2739 | yes |  |
| 8x8 | confidential signer | full+2tree | yes | 3667 | 26 | 3 | - | 2549 | 2743 | yes |  |
| 8x8 | confidential signer | full+4credential-shared | yes | 3737 | 28 | 3 | - | 2553 | 2743 | yes |  |
| 8x8 | confidential signer | full+4credential-disjoint | yes | 3833 | 31 | 3 | - | 2553 | 2743 | yes |  |
| 8x8 | confidential in-proof | min | yes | 3166 | 15 | 1 | - | 2551 | 2791 | yes |  |
| 8x8 | confidential in-proof | full | yes | 3660 | 25 | 2 | 4 | 2640 | 2836 | yes |  |
| 8x8 | confidential in-proof | full+spl | yes | 4028 | 32 | 2 | - | 2772 | 2840 | yes |  |
| 8x8 | confidential in-proof | full+data | yes | 4454 | 25 | 2 | - | 3434 | 3614 | no | 358 B |
| 8x8 | confidential in-proof | full+reply | yes | 3660 | 25 | 2 | - | 2640 | 2836 | yes |  |
| 8x8 | confidential in-proof | full+2tree | yes | 3666 | 25 | 2 | - | 2645 | 2840 | yes |  |
| 8x8 | confidential in-proof | full+4credential-shared | yes | 3736 | 27 | 2 | - | 2649 | 2840 | yes |  |
| 8x8 | confidential in-proof | full+4credential-disjoint | yes | 3832 | 30 | 2 | - | 2649 | 2840 | yes |  |
| 8x8 | anonymous hidden | min | yes | 3430 | 15 | 1 | - | 2815 | 3085 | yes |  |
| 8x8 | anonymous hidden | full | yes | 3900 | 22 | 2 | 2 | 2976 | 3212 | yes |  |
| 8x8 | anonymous hidden | full+spl | yes | 4268 | 29 | 2 | - | 3108 | 3216 | no | 172 B |
| 8x8 | anonymous hidden | full+data | yes | 4694 | 22 | 2 | - | 3770 | 3990 | no | 598 B |
| 8x8 | anonymous hidden | full+reply | yes | 4581 | 22 | 2 | - | 3657 | 3891 | no | 485 B |
| 8x8 | anonymous hidden | full+2tree | yes | 3906 | 22 | 2 | - | 2981 | 3216 | yes |  |
| 8x8 | anonymous hidden | full+4credential-shared | yes | 3976 | 24 | 2 | - | 2985 | 3216 | yes |  |
| 8x8 | anonymous hidden | full+4credential-disjoint | yes | 4072 | 27 | 2 | - | 2985 | 3216 | yes |  |
| 8x8 | anonymous public owners | min | yes | 3367 | 15 | 1 | - | 2751 | 2988 | yes |  |
| 8x8 | anonymous public owners | full | yes | 4029 | 26 | 3 | 1 | 2912 | 3115 | yes |  |
| 8x8 | anonymous public owners | full+spl | yes | 4397 | 33 | 3 | - | 3044 | 3119 | no | 301 B |
| 8x8 | anonymous public owners | full+data | yes | 4823 | 26 | 3 | - | 3706 | 3893 | no | 727 B |
| 8x8 | anonymous public owners | full+reply | yes | 4710 | 26 | 3 | - | 3593 | 3794 | no | 614 B |
| 8x8 | anonymous public owners | full+2tree | yes | 4035 | 26 | 3 | - | 2917 | 3119 | yes |  |
| 8x8 | anonymous public owners | full+4credential-shared | yes | 4105 | 28 | 3 | - | 2921 | 3119 | no | 9 B |
| 8x8 | anonymous public owners | full+4credential-disjoint | yes | 4201 | 31 | 3 | - | 2921 | 3119 | no | 105 B |
| 8x8 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 8x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x16 | confidential signer | min | yes | 4809 | 15 | 1 | - | 4193 | 4718 | no | 713 B |
| 8x16 | confidential signer | full | yes | 5399 | 26 | 3 | none | 4282 | 4763 | no | 1303 B |
| 8x16 | confidential signer | full+spl | yes | 5767 | 33 | 3 | - | 4414 | 4767 | no | 1671 B |
| 8x16 | confidential signer | full+data | yes | 6985 | 26 | 3 | - | 5868 | 6317 | no | 2889 B |
| 8x16 | confidential signer | full+reply | yes | 5399 | 26 | 3 | - | 4282 | 4763 | no | 1303 B |
| 8x16 | confidential signer | full+2tree | yes | 5405 | 26 | 3 | - | 4287 | 4767 | no | 1309 B |
| 8x16 | confidential signer | full+4credential-shared | yes | 5475 | 28 | 3 | - | 4291 | 4767 | no | 1379 B |
| 8x16 | confidential signer | full+4credential-disjoint | yes | 5571 | 31 | 3 | - | 4291 | 4767 | no | 1475 B |
| 8x16 | confidential in-proof | min | yes | 4904 | 15 | 1 | - | 4289 | 4815 | no | 808 B |
| 8x16 | confidential in-proof | full | yes | 5398 | 25 | 2 | none | 4378 | 4860 | no | 1302 B |
| 8x16 | confidential in-proof | full+spl | yes | 5766 | 32 | 2 | - | 4510 | 4864 | no | 1670 B |
| 8x16 | confidential in-proof | full+data | yes | 6984 | 25 | 2 | - | 5964 | 6414 | no | 2888 B |
| 8x16 | confidential in-proof | full+reply | yes | 5398 | 25 | 2 | - | 4378 | 4860 | no | 1302 B |
| 8x16 | confidential in-proof | full+2tree | yes | 5404 | 25 | 2 | - | 4383 | 4864 | no | 1308 B |
| 8x16 | confidential in-proof | full+4credential-shared | yes | 5474 | 27 | 2 | - | 4387 | 4864 | no | 1378 B |
| 8x16 | confidential in-proof | full+4credential-disjoint | yes | 5570 | 30 | 2 | - | 4387 | 4864 | no | 1474 B |
| 8x16 | anonymous hidden | min | yes | 5424 | 15 | 1 | - | 4809 | 5365 | no | 1328 B |
| 8x16 | anonymous hidden | full | yes | 5894 | 22 | 2 | none | 4970 | 5492 | no | 1798 B |
| 8x16 | anonymous hidden | full+spl | yes | 6262 | 29 | 2 | - | 5102 | 5496 | no | 2166 B |
| 8x16 | anonymous hidden | full+data | yes | 7480 | 22 | 2 | - | 6556 | 7046 | no | 3384 B |
| 8x16 | anonymous hidden | full+reply | yes | 7351 | 22 | 2 | - | 6427 | 6947 | no | 3255 B |
| 8x16 | anonymous hidden | full+2tree | yes | 5900 | 22 | 2 | - | 4975 | 5496 | no | 1804 B |
| 8x16 | anonymous hidden | full+4credential-shared | yes | 5970 | 24 | 2 | - | 4979 | 5496 | no | 1874 B |
| 8x16 | anonymous hidden | full+4credential-disjoint | yes | 6066 | 27 | 2 | - | 4979 | 5496 | no | 1970 B |
| 8x16 | anonymous public owners | min | yes | 5361 | 15 | 1 | - | 4745 | 5268 | no | 1265 B |
| 8x16 | anonymous public owners | full | yes | 6023 | 26 | 3 | none | 4906 | 5395 | no | 1927 B |
| 8x16 | anonymous public owners | full+spl | yes | 6391 | 33 | 3 | - | 5038 | 5399 | no | 2295 B |
| 8x16 | anonymous public owners | full+data | yes | 7609 | 26 | 3 | - | 6492 | 6949 | no | 3513 B |
| 8x16 | anonymous public owners | full+reply | yes | 7480 | 26 | 3 | - | 6363 | 6850 | no | 3384 B |
| 8x16 | anonymous public owners | full+2tree | yes | 6029 | 26 | 3 | - | 4911 | 5399 | no | 1933 B |
| 8x16 | anonymous public owners | full+4credential-shared | yes | 6099 | 28 | 3 | - | 4915 | 5399 | no | 2003 B |
| 8x16 | anonymous public owners | full+4credential-disjoint | yes | 6195 | 31 | 3 | - | 4915 | 5399 | no | 2099 B |
| 8x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x2 | confidential signer | min | yes | 2029 | 19 | 1 | - | 1281 | 1308 | yes |  |
| 12x2 | confidential signer | full | yes | 2619 | 30 | 3 | 10 | 1370 | 1353 | yes |  |
| 12x2 | confidential signer | full+spl | yes | 2987 | 37 | 3 | - | 1502 | 1357 | yes |  |
| 12x2 | confidential signer | full+data | yes | 2819 | 30 | 3 | - | 1570 | 1549 | yes |  |
| 12x2 | confidential signer | full+reply | yes | 2619 | 30 | 3 | - | 1370 | 1353 | yes |  |
| 12x2 | confidential signer | full+2tree | yes | 2626 | 30 | 3 | - | 1376 | 1357 | yes |  |
| 12x2 | confidential signer | full+4credential-shared | yes | 2696 | 32 | 3 | - | 1380 | 1357 | yes |  |
| 12x2 | confidential signer | full+4credential-disjoint | yes | 2792 | 35 | 3 | - | 1380 | 1357 | yes |  |
| 12x2 | confidential in-proof | min | yes | 2124 | 19 | 1 | - | 1377 | 1405 | yes |  |
| 12x2 | confidential in-proof | full | yes | 2618 | 29 | 2 | 10 | 1466 | 1450 | yes |  |
| 12x2 | confidential in-proof | full+spl | yes | 2986 | 36 | 2 | - | 1598 | 1454 | yes |  |
| 12x2 | confidential in-proof | full+data | yes | 2818 | 29 | 2 | - | 1666 | 1646 | yes |  |
| 12x2 | confidential in-proof | full+reply | yes | 2618 | 29 | 2 | - | 1466 | 1450 | yes |  |
| 12x2 | confidential in-proof | full+2tree | yes | 2625 | 29 | 2 | - | 1472 | 1454 | yes |  |
| 12x2 | confidential in-proof | full+4credential-shared | yes | 2695 | 31 | 2 | - | 1476 | 1454 | yes |  |
| 12x2 | confidential in-proof | full+4credential-disjoint | yes | 2791 | 34 | 2 | - | 1476 | 1454 | yes |  |
| 12x2 | anonymous hidden | min | yes | 2196 | 19 | 1 | - | 1449 | 1507 | yes |  |
| 12x2 | anonymous hidden | full | yes | 2666 | 26 | 2 | 10 | 1610 | 1634 | yes |  |
| 12x2 | anonymous hidden | full+spl | yes | 3034 | 33 | 2 | - | 1742 | 1638 | yes |  |
| 12x2 | anonymous hidden | full+data | yes | 2866 | 26 | 2 | - | 1810 | 1830 | yes |  |
| 12x2 | anonymous hidden | full+reply | yes | 2765 | 26 | 2 | - | 1709 | 1731 | yes |  |
| 12x2 | anonymous hidden | full+2tree | yes | 2673 | 26 | 2 | - | 1616 | 1638 | yes |  |
| 12x2 | anonymous hidden | full+4credential-shared | yes | 2743 | 28 | 2 | - | 1620 | 1638 | yes |  |
| 12x2 | anonymous hidden | full+4credential-disjoint | yes | 2839 | 31 | 2 | - | 1620 | 1638 | yes |  |
| 12x2 | anonymous public owners | min | yes | 2133 | 19 | 1 | - | 1385 | 1410 | yes |  |
| 12x2 | anonymous public owners | full | yes | 2795 | 30 | 3 | 10 | 1546 | 1537 | yes |  |
| 12x2 | anonymous public owners | full+spl | yes | 3163 | 37 | 3 | - | 1678 | 1541 | yes |  |
| 12x2 | anonymous public owners | full+data | yes | 2995 | 30 | 3 | - | 1746 | 1733 | yes |  |
| 12x2 | anonymous public owners | full+reply | yes | 2894 | 30 | 3 | - | 1645 | 1634 | yes |  |
| 12x2 | anonymous public owners | full+2tree | yes | 2802 | 30 | 3 | - | 1552 | 1541 | yes |  |
| 12x2 | anonymous public owners | full+4credential-shared | yes | 2872 | 32 | 3 | - | 1556 | 1541 | yes |  |
| 12x2 | anonymous public owners | full+4credential-disjoint | yes | 2968 | 35 | 3 | - | 1556 | 1541 | yes |  |
| 12x2 | confidential entry | min | yes | 4437 | 19 | 1 | - | 3689 | 3716 | no | 341 B |
| 12x2 | confidential entry | full | yes | 5027 | 30 | 3 | none | 3778 | 3761 | no | 931 B |
| 12x2 | confidential entry | full+spl | yes | 5395 | 37 | 3 | - | 3910 | 3765 | no | 1299 B |
| 12x2 | confidential entry | full+data | yes | 5227 | 30 | 3 | - | 3978 | 3957 | no | 1131 B |
| 12x2 | confidential entry | full+reply | yes | 5027 | 30 | 3 | - | 3778 | 3761 | no | 931 B |
| 12x2 | confidential entry | full+2tree | yes | 5034 | 30 | 3 | - | 3784 | 3765 | no | 938 B |
| 12x2 | confidential entry | full+4credential-shared | yes | 5104 | 32 | 3 | - | 3788 | 3765 | no | 1008 B |
| 12x2 | confidential entry | full+4credential-disjoint | yes | 5200 | 35 | 3 | - | 3788 | 3765 | no | 1104 B |
| 12x2 | anonymous entry | min | yes | 4636 | 19 | 1 | - | 3889 | 3915 | no | 540 B |
| 12x2 | anonymous entry | full | yes | 5106 | 26 | 2 | none | 4050 | 4042 | no | 1010 B |
| 12x2 | anonymous entry | full+spl | yes | 5474 | 33 | 2 | - | 4182 | 4046 | no | 1378 B |
| 12x2 | anonymous entry | full+data | yes | 5306 | 26 | 2 | - | 4250 | 4238 | no | 1210 B |
| 12x2 | anonymous entry | full+reply | yes | 5205 | 26 | 2 | - | 4149 | 4139 | no | 1109 B |
| 12x2 | anonymous entry | full+2tree | yes | 5113 | 26 | 2 | - | 4056 | 4046 | no | 1017 B |
| 12x2 | anonymous entry | full+4credential-shared | yes | 5183 | 28 | 2 | - | 4060 | 4046 | no | 1087 B |
| 12x2 | anonymous entry | full+4credential-disjoint | yes | 5279 | 31 | 2 | - | 4060 | 4046 | no | 1183 B |
| 12x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x4 | confidential signer | min | yes | 2463 | 19 | 1 | - | 1715 | 1814 | yes |  |
| 12x4 | confidential signer | full | yes | 3053 | 30 | 3 | 10 | 1804 | 1859 | yes |  |
| 12x4 | confidential signer | full+spl | yes | 3421 | 37 | 3 | - | 1936 | 1863 | yes |  |
| 12x4 | confidential signer | full+data | yes | 3451 | 30 | 3 | - | 2202 | 2249 | yes |  |
| 12x4 | confidential signer | full+reply | yes | 3053 | 30 | 3 | - | 1804 | 1859 | yes |  |
| 12x4 | confidential signer | full+2tree | yes | 3060 | 30 | 3 | - | 1810 | 1863 | yes |  |
| 12x4 | confidential signer | full+4credential-shared | yes | 3130 | 32 | 3 | - | 1814 | 1863 | yes |  |
| 12x4 | confidential signer | full+4credential-disjoint | yes | 3226 | 35 | 3 | - | 1814 | 1863 | yes |  |
| 12x4 | confidential in-proof | min | yes | 2558 | 19 | 1 | - | 1811 | 1911 | yes |  |
| 12x4 | confidential in-proof | full | yes | 3052 | 29 | 2 | 10 | 1900 | 1956 | yes |  |
| 12x4 | confidential in-proof | full+spl | yes | 3420 | 36 | 2 | - | 2032 | 1960 | yes |  |
| 12x4 | confidential in-proof | full+data | yes | 3450 | 29 | 2 | - | 2298 | 2346 | yes |  |
| 12x4 | confidential in-proof | full+reply | yes | 3052 | 29 | 2 | - | 1900 | 1956 | yes |  |
| 12x4 | confidential in-proof | full+2tree | yes | 3059 | 29 | 2 | - | 1906 | 1960 | yes |  |
| 12x4 | confidential in-proof | full+4credential-shared | yes | 3129 | 31 | 2 | - | 1910 | 1960 | yes |  |
| 12x4 | confidential in-proof | full+4credential-disjoint | yes | 3225 | 34 | 2 | - | 1910 | 1960 | yes |  |
| 12x4 | anonymous hidden | min | yes | 2694 | 19 | 1 | - | 1947 | 2077 | yes |  |
| 12x4 | anonymous hidden | full | yes | 3164 | 26 | 2 | 9 | 2108 | 2204 | yes |  |
| 12x4 | anonymous hidden | full+spl | yes | 3532 | 33 | 2 | - | 2240 | 2208 | yes |  |
| 12x4 | anonymous hidden | full+data | yes | 3562 | 26 | 2 | - | 2506 | 2594 | yes |  |
| 12x4 | anonymous hidden | full+reply | yes | 3457 | 26 | 2 | - | 2401 | 2495 | yes |  |
| 12x4 | anonymous hidden | full+2tree | yes | 3171 | 26 | 2 | - | 2114 | 2208 | yes |  |
| 12x4 | anonymous hidden | full+4credential-shared | yes | 3241 | 28 | 2 | - | 2118 | 2208 | yes |  |
| 12x4 | anonymous hidden | full+4credential-disjoint | yes | 3337 | 31 | 2 | - | 2118 | 2208 | yes |  |
| 12x4 | anonymous public owners | min | yes | 2631 | 19 | 1 | - | 1883 | 1980 | yes |  |
| 12x4 | anonymous public owners | full | yes | 3293 | 30 | 3 | 9 | 2044 | 2107 | yes |  |
| 12x4 | anonymous public owners | full+spl | yes | 3661 | 37 | 3 | - | 2176 | 2111 | yes |  |
| 12x4 | anonymous public owners | full+data | yes | 3691 | 30 | 3 | - | 2442 | 2497 | yes |  |
| 12x4 | anonymous public owners | full+reply | yes | 3586 | 30 | 3 | - | 2337 | 2398 | yes |  |
| 12x4 | anonymous public owners | full+2tree | yes | 3300 | 30 | 3 | - | 2050 | 2111 | yes |  |
| 12x4 | anonymous public owners | full+4credential-shared | yes | 3370 | 32 | 3 | - | 2054 | 2111 | yes |  |
| 12x4 | anonymous public owners | full+4credential-disjoint | yes | 3466 | 35 | 3 | - | 2054 | 2111 | yes |  |
| 12x4 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x8 | confidential signer | min | yes | 3331 | 19 | 1 | - | 2583 | 2826 | yes |  |
| 12x8 | confidential signer | full | yes | 3921 | 30 | 3 | 2 | 2672 | 2871 | yes |  |
| 12x8 | confidential signer | full+spl | yes | 4289 | 37 | 3 | - | 2804 | 2875 | no | 193 B |
| 12x8 | confidential signer | full+data | yes | 4715 | 30 | 3 | - | 3466 | 3649 | no | 619 B |
| 12x8 | confidential signer | full+reply | yes | 3921 | 30 | 3 | - | 2672 | 2871 | yes |  |
| 12x8 | confidential signer | full+2tree | yes | 3928 | 30 | 3 | - | 2678 | 2875 | yes |  |
| 12x8 | confidential signer | full+4credential-shared | yes | 3998 | 32 | 3 | - | 2682 | 2875 | yes |  |
| 12x8 | confidential signer | full+4credential-disjoint | yes | 4094 | 35 | 3 | - | 2682 | 2875 | yes |  |
| 12x8 | confidential in-proof | min | yes | 3426 | 19 | 1 | - | 2679 | 2923 | yes |  |
| 12x8 | confidential in-proof | full | yes | 3920 | 29 | 2 | 1 | 2768 | 2968 | yes |  |
| 12x8 | confidential in-proof | full+spl | yes | 4288 | 36 | 2 | - | 2900 | 2972 | no | 192 B |
| 12x8 | confidential in-proof | full+data | yes | 4714 | 29 | 2 | - | 3562 | 3746 | no | 618 B |
| 12x8 | confidential in-proof | full+reply | yes | 3920 | 29 | 2 | - | 2768 | 2968 | yes |  |
| 12x8 | confidential in-proof | full+2tree | yes | 3927 | 29 | 2 | - | 2774 | 2972 | yes |  |
| 12x8 | confidential in-proof | full+4credential-shared | yes | 3997 | 31 | 2 | - | 2778 | 2972 | yes |  |
| 12x8 | confidential in-proof | full+4credential-disjoint | yes | 4093 | 34 | 2 | - | 2778 | 2972 | yes |  |
| 12x8 | anonymous hidden | min | yes | 3690 | 19 | 1 | - | 2943 | 3217 | yes |  |
| 12x8 | anonymous hidden | full | yes | 4160 | 26 | 2 | none | 3104 | 3344 | no | 64 B |
| 12x8 | anonymous hidden | full+spl | yes | 4528 | 33 | 2 | - | 3236 | 3348 | no | 432 B |
| 12x8 | anonymous hidden | full+data | yes | 4954 | 26 | 2 | - | 3898 | 4122 | no | 858 B |
| 12x8 | anonymous hidden | full+reply | yes | 4841 | 26 | 2 | - | 3785 | 4023 | no | 745 B |
| 12x8 | anonymous hidden | full+2tree | yes | 4167 | 26 | 2 | - | 3110 | 3348 | no | 71 B |
| 12x8 | anonymous hidden | full+4credential-shared | yes | 4237 | 28 | 2 | - | 3114 | 3348 | no | 141 B |
| 12x8 | anonymous hidden | full+4credential-disjoint | yes | 4333 | 31 | 2 | - | 3114 | 3348 | no | 237 B |
| 12x8 | anonymous public owners | min | yes | 3627 | 19 | 1 | - | 2879 | 3120 | yes |  |
| 12x8 | anonymous public owners | full | yes | 4289 | 30 | 3 | none | 3040 | 3247 | no | 193 B |
| 12x8 | anonymous public owners | full+spl | yes | 4657 | 37 | 3 | - | 3172 | 3251 | no | 561 B |
| 12x8 | anonymous public owners | full+data | yes | 5083 | 30 | 3 | - | 3834 | 4025 | no | 987 B |
| 12x8 | anonymous public owners | full+reply | yes | 4970 | 30 | 3 | - | 3721 | 3926 | no | 874 B |
| 12x8 | anonymous public owners | full+2tree | yes | 4296 | 30 | 3 | - | 3046 | 3251 | no | 200 B |
| 12x8 | anonymous public owners | full+4credential-shared | yes | 4366 | 32 | 3 | - | 3050 | 3251 | no | 270 B |
| 12x8 | anonymous public owners | full+4credential-disjoint | yes | 4462 | 35 | 3 | - | 3050 | 3251 | no | 366 B |
| 12x8 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x2 | confidential signer | min | yes | 2289 | 23 | 1 | - | 1409 | 1440 | yes |  |
| 16x2 | confidential signer | full | yes | 2879 | 34 | 3 | 10 | 1498 | 1485 | yes |  |
| 16x2 | confidential signer | full+spl | yes | 3247 | 41 | 3 | - | 1630 | 1489 | yes |  |
| 16x2 | confidential signer | full+data | yes | 3079 | 34 | 3 | - | 1698 | 1681 | yes |  |
| 16x2 | confidential signer | full+reply | yes | 2879 | 34 | 3 | - | 1498 | 1485 | yes |  |
| 16x2 | confidential signer | full+2tree | yes | 2886 | 34 | 3 | - | 1504 | 1489 | yes |  |
| 16x2 | confidential signer | full+4credential-shared | yes | 2956 | 36 | 3 | - | 1508 | 1489 | yes |  |
| 16x2 | confidential signer | full+4credential-disjoint | yes | 3052 | 39 | 3 | - | 1508 | 1489 | yes |  |
| 16x2 | confidential in-proof | min | yes | 2384 | 23 | 1 | - | 1505 | 1537 | yes |  |
| 16x2 | confidential in-proof | full | yes | 2878 | 33 | 2 | 10 | 1594 | 1582 | yes |  |
| 16x2 | confidential in-proof | full+spl | yes | 3246 | 40 | 2 | - | 1726 | 1586 | yes |  |
| 16x2 | confidential in-proof | full+data | yes | 3078 | 33 | 2 | - | 1794 | 1778 | yes |  |
| 16x2 | confidential in-proof | full+reply | yes | 2878 | 33 | 2 | - | 1594 | 1582 | yes |  |
| 16x2 | confidential in-proof | full+2tree | yes | 2885 | 33 | 2 | - | 1600 | 1586 | yes |  |
| 16x2 | confidential in-proof | full+4credential-shared | yes | 2955 | 35 | 2 | - | 1604 | 1586 | yes |  |
| 16x2 | confidential in-proof | full+4credential-disjoint | yes | 3051 | 38 | 2 | - | 1604 | 1586 | yes |  |
| 16x2 | anonymous hidden | min | yes | 2456 | 23 | 1 | - | 1577 | 1639 | yes |  |
| 16x2 | anonymous hidden | full | yes | 2926 | 30 | 2 | 10 | 1738 | 1766 | yes |  |
| 16x2 | anonymous hidden | full+spl | yes | 3294 | 37 | 2 | - | 1870 | 1770 | yes |  |
| 16x2 | anonymous hidden | full+data | yes | 3126 | 30 | 2 | - | 1938 | 1962 | yes |  |
| 16x2 | anonymous hidden | full+reply | yes | 3025 | 30 | 2 | - | 1837 | 1863 | yes |  |
| 16x2 | anonymous hidden | full+2tree | yes | 2933 | 30 | 2 | - | 1744 | 1770 | yes |  |
| 16x2 | anonymous hidden | full+4credential-shared | yes | 3003 | 32 | 2 | - | 1748 | 1770 | yes |  |
| 16x2 | anonymous hidden | full+4credential-disjoint | yes | 3099 | 35 | 2 | - | 1748 | 1770 | yes |  |
| 16x2 | anonymous public owners | min | yes | 2393 | 23 | 1 | - | 1513 | 1542 | yes |  |
| 16x2 | anonymous public owners | full | yes | 3055 | 34 | 3 | 10 | 1674 | 1669 | yes |  |
| 16x2 | anonymous public owners | full+spl | yes | 3423 | 41 | 3 | - | 1806 | 1673 | yes |  |
| 16x2 | anonymous public owners | full+data | yes | 3255 | 34 | 3 | - | 1874 | 1865 | yes |  |
| 16x2 | anonymous public owners | full+reply | yes | 3154 | 34 | 3 | - | 1773 | 1766 | yes |  |
| 16x2 | anonymous public owners | full+2tree | yes | 3062 | 34 | 3 | - | 1680 | 1673 | yes |  |
| 16x2 | anonymous public owners | full+4credential-shared | yes | 3132 | 36 | 3 | - | 1684 | 1673 | yes |  |
| 16x2 | anonymous public owners | full+4credential-disjoint | yes | 3228 | 39 | 3 | - | 1684 | 1673 | yes |  |
| 16x2 | confidential entry | min | yes | 5497 | 23 | 1 | - | 4617 | 4648 | no | 1401 B |
| 16x2 | confidential entry | full | yes | 6087 | 34 | 3 | none | 4706 | 4693 | no | 1991 B |
| 16x2 | confidential entry | full+spl | yes | 6455 | 41 | 3 | - | 4838 | 4697 | no | 2359 B |
| 16x2 | confidential entry | full+data | yes | 6287 | 34 | 3 | - | 4906 | 4889 | no | 2191 B |
| 16x2 | confidential entry | full+reply | yes | 6087 | 34 | 3 | - | 4706 | 4693 | no | 1991 B |
| 16x2 | confidential entry | full+2tree | yes | 6094 | 34 | 3 | - | 4712 | 4697 | no | 1998 B |
| 16x2 | confidential entry | full+4credential-shared | yes | 6164 | 36 | 3 | - | 4716 | 4697 | no | 2068 B |
| 16x2 | confidential entry | full+4credential-disjoint | yes | 6260 | 39 | 3 | - | 4716 | 4697 | no | 2164 B |
| 16x2 | anonymous entry | min | yes | 5696 | 23 | 1 | - | 4817 | 4847 | no | 1600 B |
| 16x2 | anonymous entry | full | yes | 6166 | 30 | 2 | none | 4978 | 4974 | no | 2070 B |
| 16x2 | anonymous entry | full+spl | yes | 6534 | 37 | 2 | - | 5110 | 4978 | no | 2438 B |
| 16x2 | anonymous entry | full+data | yes | 6366 | 30 | 2 | - | 5178 | 5170 | no | 2270 B |
| 16x2 | anonymous entry | full+reply | yes | 6265 | 30 | 2 | - | 5077 | 5071 | no | 2169 B |
| 16x2 | anonymous entry | full+2tree | yes | 6173 | 30 | 2 | - | 4984 | 4978 | no | 2077 B |
| 16x2 | anonymous entry | full+4credential-shared | yes | 6243 | 32 | 2 | - | 4988 | 4978 | no | 2147 B |
| 16x2 | anonymous entry | full+4credential-disjoint | yes | 6339 | 35 | 2 | - | 4988 | 4978 | no | 2243 B |
| 16x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x4 | confidential signer | min | yes | 2723 | 23 | 1 | - | 1843 | 1946 | yes |  |
| 16x4 | confidential signer | full | yes | 3313 | 34 | 3 | 9 | 1932 | 1991 | yes |  |
| 16x4 | confidential signer | full+spl | yes | 3681 | 41 | 3 | - | 2064 | 1995 | yes |  |
| 16x4 | confidential signer | full+data | yes | 3711 | 34 | 3 | - | 2330 | 2381 | yes |  |
| 16x4 | confidential signer | full+reply | yes | 3313 | 34 | 3 | - | 1932 | 1991 | yes |  |
| 16x4 | confidential signer | full+2tree | yes | 3320 | 34 | 3 | - | 1938 | 1995 | yes |  |
| 16x4 | confidential signer | full+4credential-shared | yes | 3390 | 36 | 3 | - | 1942 | 1995 | yes |  |
| 16x4 | confidential signer | full+4credential-disjoint | yes | 3486 | 39 | 3 | - | 1942 | 1995 | yes |  |
| 16x4 | confidential in-proof | min | yes | 2818 | 23 | 1 | - | 1939 | 2043 | yes |  |
| 16x4 | confidential in-proof | full | yes | 3312 | 33 | 2 | 8 | 2028 | 2088 | yes |  |
| 16x4 | confidential in-proof | full+spl | yes | 3680 | 40 | 2 | - | 2160 | 2092 | yes |  |
| 16x4 | confidential in-proof | full+data | yes | 3710 | 33 | 2 | - | 2426 | 2478 | yes |  |
| 16x4 | confidential in-proof | full+reply | yes | 3312 | 33 | 2 | - | 2028 | 2088 | yes |  |
| 16x4 | confidential in-proof | full+2tree | yes | 3319 | 33 | 2 | - | 2034 | 2092 | yes |  |
| 16x4 | confidential in-proof | full+4credential-shared | yes | 3389 | 35 | 2 | - | 2038 | 2092 | yes |  |
| 16x4 | confidential in-proof | full+4credential-disjoint | yes | 3485 | 38 | 2 | - | 2038 | 2092 | yes |  |
| 16x4 | anonymous hidden | min | yes | 2954 | 23 | 1 | - | 2075 | 2209 | yes |  |
| 16x4 | anonymous hidden | full | yes | 3424 | 30 | 2 | 6 | 2236 | 2336 | yes |  |
| 16x4 | anonymous hidden | full+spl | yes | 3792 | 37 | 2 | - | 2368 | 2340 | yes |  |
| 16x4 | anonymous hidden | full+data | yes | 3822 | 30 | 2 | - | 2634 | 2726 | yes |  |
| 16x4 | anonymous hidden | full+reply | yes | 3717 | 30 | 2 | - | 2529 | 2627 | yes |  |
| 16x4 | anonymous hidden | full+2tree | yes | 3431 | 30 | 2 | - | 2242 | 2340 | yes |  |
| 16x4 | anonymous hidden | full+4credential-shared | yes | 3501 | 32 | 2 | - | 2246 | 2340 | yes |  |
| 16x4 | anonymous hidden | full+4credential-disjoint | yes | 3597 | 35 | 2 | - | 2246 | 2340 | yes |  |
| 16x4 | anonymous public owners | min | yes | 2891 | 23 | 1 | - | 2011 | 2112 | yes |  |
| 16x4 | anonymous public owners | full | yes | 3553 | 34 | 3 | 6 | 2172 | 2239 | yes |  |
| 16x4 | anonymous public owners | full+spl | yes | 3921 | 41 | 3 | - | 2304 | 2243 | yes |  |
| 16x4 | anonymous public owners | full+data | yes | 3951 | 34 | 3 | - | 2570 | 2629 | yes |  |
| 16x4 | anonymous public owners | full+reply | yes | 3846 | 34 | 3 | - | 2465 | 2530 | yes |  |
| 16x4 | anonymous public owners | full+2tree | yes | 3560 | 34 | 3 | - | 2178 | 2243 | yes |  |
| 16x4 | anonymous public owners | full+4credential-shared | yes | 3630 | 36 | 3 | - | 2182 | 2243 | yes |  |
| 16x4 | anonymous public owners | full+4credential-disjoint | yes | 3726 | 39 | 3 | - | 2182 | 2243 | yes |  |
| 16x4 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x8 | confidential signer | min | yes | 3591 | 23 | 1 | - | 2711 | 2958 | yes |  |
| 16x8 | confidential signer | full | yes | 4181 | 34 | 3 | none | 2800 | 3003 | no | 85 B |
| 16x8 | confidential signer | full+spl | yes | 4549 | 41 | 3 | - | 2932 | 3007 | no | 453 B |
| 16x8 | confidential signer | full+data | yes | 4975 | 34 | 3 | - | 3594 | 3781 | no | 879 B |
| 16x8 | confidential signer | full+reply | yes | 4181 | 34 | 3 | - | 2800 | 3003 | no | 85 B |
| 16x8 | confidential signer | full+2tree | yes | 4188 | 34 | 3 | - | 2806 | 3007 | no | 92 B |
| 16x8 | confidential signer | full+4credential-shared | yes | 4258 | 36 | 3 | - | 2810 | 3007 | no | 162 B |
| 16x8 | confidential signer | full+4credential-disjoint | yes | 4354 | 39 | 3 | - | 2810 | 3007 | no | 258 B |
| 16x8 | confidential in-proof | min | yes | 3686 | 23 | 1 | - | 2807 | 3055 | yes |  |
| 16x8 | confidential in-proof | full | yes | 4180 | 33 | 2 | none | 2896 | 3100 | no | 84 B |
| 16x8 | confidential in-proof | full+spl | yes | 4548 | 40 | 2 | - | 3028 | 3104 | no | 452 B |
| 16x8 | confidential in-proof | full+data | yes | 4974 | 33 | 2 | - | 3690 | 3878 | no | 878 B |
| 16x8 | confidential in-proof | full+reply | yes | 4180 | 33 | 2 | - | 2896 | 3100 | no | 84 B |
| 16x8 | confidential in-proof | full+2tree | yes | 4187 | 33 | 2 | - | 2902 | 3104 | no | 91 B |
| 16x8 | confidential in-proof | full+4credential-shared | yes | 4257 | 35 | 2 | - | 2906 | 3104 | no | 161 B |
| 16x8 | confidential in-proof | full+4credential-disjoint | yes | 4353 | 38 | 2 | - | 2906 | 3104 | no | 257 B |
| 16x8 | anonymous hidden | min | yes | 3950 | 23 | 1 | - | 3071 | 3349 | yes |  |
| 16x8 | anonymous hidden | full | yes | 4420 | 30 | 2 | none | 3232 | 3476 | no | 324 B |
| 16x8 | anonymous hidden | full+spl | yes | 4788 | 37 | 2 | - | 3364 | 3480 | no | 692 B |
| 16x8 | anonymous hidden | full+data | yes | 5214 | 30 | 2 | - | 4026 | 4254 | no | 1118 B |
| 16x8 | anonymous hidden | full+reply | yes | 5101 | 30 | 2 | - | 3913 | 4155 | no | 1005 B |
| 16x8 | anonymous hidden | full+2tree | yes | 4427 | 30 | 2 | - | 3238 | 3480 | no | 331 B |
| 16x8 | anonymous hidden | full+4credential-shared | yes | 4497 | 32 | 2 | - | 3242 | 3480 | no | 401 B |
| 16x8 | anonymous hidden | full+4credential-disjoint | yes | 4593 | 35 | 2 | - | 3242 | 3480 | no | 497 B |
| 16x8 | anonymous public owners | min | yes | 3887 | 23 | 1 | - | 3007 | 3252 | yes |  |
| 16x8 | anonymous public owners | full | yes | 4549 | 34 | 3 | none | 3168 | 3379 | no | 453 B |
| 16x8 | anonymous public owners | full+spl | yes | 4917 | 41 | 3 | - | 3300 | 3383 | no | 821 B |
| 16x8 | anonymous public owners | full+data | yes | 5343 | 34 | 3 | - | 3962 | 4157 | no | 1247 B |
| 16x8 | anonymous public owners | full+reply | yes | 5230 | 34 | 3 | - | 3849 | 4058 | no | 1134 B |
| 16x8 | anonymous public owners | full+2tree | yes | 4556 | 34 | 3 | - | 3174 | 3383 | no | 460 B |
| 16x8 | anonymous public owners | full+4credential-shared | yes | 4626 | 36 | 3 | - | 3178 | 3383 | no | 530 B |
| 16x8 | anonymous public owners | full+4credential-disjoint | yes | 4722 | 39 | 3 | - | 3178 | 3383 | no | 626 B |
| 16x8 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 24x2 | confidential signer | min | yes | 2809 | 31 | 1 | - | 1665 | 1704 | yes |  |
| 24x2 | confidential signer | full | yes | 3399 | 42 | 3 | 8 | 1754 | 1749 | yes |  |
| 24x2 | confidential signer | full+spl | yes | 3767 | 49 | 3 | - | 1886 | 1753 | yes |  |
| 24x2 | confidential signer | full+data | yes | 3599 | 42 | 3 | - | 1954 | 1945 | yes |  |
| 24x2 | confidential signer | full+reply | yes | 3399 | 42 | 3 | - | 1754 | 1749 | yes |  |
| 24x2 | confidential signer | full+2tree | yes | 3407 | 42 | 3 | - | 1761 | 1753 | yes |  |
| 24x2 | confidential signer | full+4credential-shared | yes | 3477 | 44 | 3 | - | 1765 | 1753 | yes |  |
| 24x2 | confidential signer | full+4credential-disjoint | yes | 3573 | 47 | 3 | - | 1765 | 1753 | yes |  |
| 24x2 | confidential in-proof | min | yes | 2904 | 31 | 1 | - | 1761 | 1801 | yes |  |
| 24x2 | confidential in-proof | full | yes | 3398 | 41 | 2 | 7 | 1850 | 1846 | yes |  |
| 24x2 | confidential in-proof | full+spl | yes | 3766 | 48 | 2 | - | 1982 | 1850 | yes |  |
| 24x2 | confidential in-proof | full+data | yes | 3598 | 41 | 2 | - | 2050 | 2042 | yes |  |
| 24x2 | confidential in-proof | full+reply | yes | 3398 | 41 | 2 | - | 1850 | 1846 | yes |  |
| 24x2 | confidential in-proof | full+2tree | yes | 3406 | 41 | 2 | - | 1857 | 1850 | yes |  |
| 24x2 | confidential in-proof | full+4credential-shared | yes | 3476 | 43 | 2 | - | 1861 | 1850 | yes |  |
| 24x2 | confidential in-proof | full+4credential-disjoint | yes | 3572 | 46 | 2 | - | 1861 | 1850 | yes |  |
| 24x2 | anonymous hidden | min | yes | 2976 | 31 | 1 | - | 1833 | 1903 | yes |  |
| 24x2 | anonymous hidden | full | yes | 3446 | 38 | 2 | 6 | 1994 | 2030 | yes |  |
| 24x2 | anonymous hidden | full+spl | yes | 3814 | 45 | 2 | - | 2126 | 2034 | yes |  |
| 24x2 | anonymous hidden | full+data | yes | 3646 | 38 | 2 | - | 2194 | 2226 | yes |  |
| 24x2 | anonymous hidden | full+reply | yes | 3545 | 38 | 2 | - | 2093 | 2127 | yes |  |
| 24x2 | anonymous hidden | full+2tree | yes | 3454 | 38 | 2 | - | 2001 | 2034 | yes |  |
| 24x2 | anonymous hidden | full+4credential-shared | yes | 3524 | 40 | 2 | - | 2005 | 2034 | yes |  |
| 24x2 | anonymous hidden | full+4credential-disjoint | yes | 3620 | 43 | 2 | - | 2005 | 2034 | yes |  |
| 24x2 | anonymous public owners | min | yes | 2913 | 31 | 1 | - | 1769 | 1806 | yes |  |
| 24x2 | anonymous public owners | full | yes | 3575 | 42 | 3 | 6 | 1930 | 1933 | yes |  |
| 24x2 | anonymous public owners | full+spl | yes | 3943 | 49 | 3 | - | 2062 | 1937 | yes |  |
| 24x2 | anonymous public owners | full+data | yes | 3775 | 42 | 3 | - | 2130 | 2129 | yes |  |
| 24x2 | anonymous public owners | full+reply | yes | 3674 | 42 | 3 | - | 2029 | 2030 | yes |  |
| 24x2 | anonymous public owners | full+2tree | yes | 3583 | 42 | 3 | - | 1937 | 1937 | yes |  |
| 24x2 | anonymous public owners | full+4credential-shared | yes | 3653 | 44 | 3 | - | 1941 | 1937 | yes |  |
| 24x2 | anonymous public owners | full+4credential-disjoint | yes | 3749 | 47 | 3 | - | 1941 | 1937 | yes |  |
| 24x2 | confidential entry | min | yes | 7617 | 31 | 1 | - | 6473 | 6512 | no | 3521 B |
| 24x2 | confidential entry | full | yes | 8207 | 42 | 3 | none | 6562 | 6557 | no | 4111 B |
| 24x2 | confidential entry | full+spl | yes | 8575 | 49 | 3 | - | 6694 | 6561 | no | 4479 B |
| 24x2 | confidential entry | full+data | yes | 8407 | 42 | 3 | - | 6762 | 6753 | no | 4311 B |
| 24x2 | confidential entry | full+reply | yes | 8207 | 42 | 3 | - | 6562 | 6557 | no | 4111 B |
| 24x2 | confidential entry | full+2tree | yes | 8215 | 42 | 3 | - | 6569 | 6561 | no | 4119 B |
| 24x2 | confidential entry | full+4credential-shared | yes | 8285 | 44 | 3 | - | 6573 | 6561 | no | 4189 B |
| 24x2 | confidential entry | full+4credential-disjoint | yes | 8381 | 47 | 3 | - | 6573 | 6561 | no | 4285 B |
| 24x2 | anonymous entry | min | yes | 7816 | 31 | 1 | - | 6673 | 6711 | no | 3720 B |
| 24x2 | anonymous entry | full | yes | 8286 | 38 | 2 | none | 6834 | 6838 | no | 4190 B |
| 24x2 | anonymous entry | full+spl | yes | 8654 | 45 | 2 | - | 6966 | 6842 | no | 4558 B |
| 24x2 | anonymous entry | full+data | yes | 8486 | 38 | 2 | - | 7034 | 7034 | no | 4390 B |
| 24x2 | anonymous entry | full+reply | yes | 8385 | 38 | 2 | - | 6933 | 6935 | no | 4289 B |
| 24x2 | anonymous entry | full+2tree | yes | 8294 | 38 | 2 | - | 6841 | 6842 | no | 4198 B |
| 24x2 | anonymous entry | full+4credential-shared | yes | 8364 | 40 | 2 | - | 6845 | 6842 | no | 4268 B |
| 24x2 | anonymous entry | full+4credential-disjoint | yes | 8460 | 43 | 2 | - | 6845 | 6842 | no | 4364 B |
| 24x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 24x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 24x4 | confidential signer | min | yes | 3243 | 31 | 1 | - | 2099 | 2210 | yes |  |
| 24x4 | confidential signer | full | yes | 3833 | 42 | 3 | 3 | 2188 | 2255 | yes |  |
| 24x4 | confidential signer | full+spl | yes | 4201 | 49 | 3 | - | 2320 | 2259 | no | 105 B |
| 24x4 | confidential signer | full+data | yes | 4231 | 42 | 3 | - | 2586 | 2645 | no | 135 B |
| 24x4 | confidential signer | full+reply | yes | 3833 | 42 | 3 | - | 2188 | 2255 | yes |  |
| 24x4 | confidential signer | full+2tree | yes | 3841 | 42 | 3 | - | 2195 | 2259 | yes |  |
| 24x4 | confidential signer | full+4credential-shared | yes | 3911 | 44 | 3 | - | 2199 | 2259 | yes |  |
| 24x4 | confidential signer | full+4credential-disjoint | yes | 4007 | 47 | 3 | - | 2199 | 2259 | yes |  |
| 24x4 | confidential in-proof | min | yes | 3338 | 31 | 1 | - | 2195 | 2307 | yes |  |
| 24x4 | confidential in-proof | full | yes | 3832 | 41 | 2 | 2 | 2284 | 2352 | yes |  |
| 24x4 | confidential in-proof | full+spl | yes | 4200 | 48 | 2 | - | 2416 | 2356 | no | 104 B |
| 24x4 | confidential in-proof | full+data | yes | 4230 | 41 | 2 | - | 2682 | 2742 | no | 134 B |
| 24x4 | confidential in-proof | full+reply | yes | 3832 | 41 | 2 | - | 2284 | 2352 | yes |  |
| 24x4 | confidential in-proof | full+2tree | yes | 3840 | 41 | 2 | - | 2291 | 2356 | yes |  |
| 24x4 | confidential in-proof | full+4credential-shared | yes | 3910 | 43 | 2 | - | 2295 | 2356 | yes |  |
| 24x4 | confidential in-proof | full+4credential-disjoint | yes | 4006 | 46 | 2 | - | 2295 | 2356 | yes |  |
| 24x4 | anonymous hidden | min | yes | 3474 | 31 | 1 | - | 2331 | 2473 | yes |  |
| 24x4 | anonymous hidden | full | yes | 3944 | 38 | 2 | 1 | 2492 | 2600 | yes |  |
| 24x4 | anonymous hidden | full+spl | yes | 4312 | 45 | 2 | - | 2624 | 2604 | no | 216 B |
| 24x4 | anonymous hidden | full+data | yes | 4342 | 38 | 2 | - | 2890 | 2990 | no | 246 B |
| 24x4 | anonymous hidden | full+reply | yes | 4237 | 38 | 2 | - | 2785 | 2891 | no | 141 B |
| 24x4 | anonymous hidden | full+2tree | yes | 3952 | 38 | 2 | - | 2499 | 2604 | yes |  |
| 24x4 | anonymous hidden | full+4credential-shared | yes | 4022 | 40 | 2 | - | 2503 | 2604 | yes |  |
| 24x4 | anonymous hidden | full+4credential-disjoint | yes | 4118 | 43 | 2 | - | 2503 | 2604 | no | 22 B |
| 24x4 | anonymous public owners | min | yes | 3411 | 31 | 1 | - | 2267 | 2376 | yes |  |
| 24x4 | anonymous public owners | full | yes | 4073 | 42 | 3 | 1 | 2428 | 2503 | yes |  |
| 24x4 | anonymous public owners | full+spl | yes | 4441 | 49 | 3 | - | 2560 | 2507 | no | 345 B |
| 24x4 | anonymous public owners | full+data | yes | 4471 | 42 | 3 | - | 2826 | 2893 | no | 375 B |
| 24x4 | anonymous public owners | full+reply | yes | 4366 | 42 | 3 | - | 2721 | 2794 | no | 270 B |
| 24x4 | anonymous public owners | full+2tree | yes | 4081 | 42 | 3 | - | 2435 | 2507 | yes |  |
| 24x4 | anonymous public owners | full+4credential-shared | yes | 4151 | 44 | 3 | - | 2439 | 2507 | no | 55 B |
| 24x4 | anonymous public owners | full+4credential-disjoint | yes | 4247 | 47 | 3 | - | 2439 | 2507 | no | 151 B |
| 24x4 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 24x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 32x2 | confidential signer | min | yes | 3329 | 39 | 1 | - | 1921 | 1968 | yes |  |
| 32x2 | confidential signer | full | yes | 3919 | 50 | 3 | 2 | 2010 | 2013 | yes |  |
| 32x2 | confidential signer | full+spl | yes | 4287 | 57 | 3 | - | 2142 | 2017 | no | 191 B |
| 32x2 | confidential signer | full+data | yes | 4119 | 50 | 3 | - | 2210 | 2209 | no | 23 B |
| 32x2 | confidential signer | full+reply | yes | 3919 | 50 | 3 | - | 2010 | 2013 | yes |  |
| 32x2 | confidential signer | full+2tree | yes | 3928 | 50 | 3 | - | 2018 | 2017 | yes |  |
| 32x2 | confidential signer | full+4credential-shared | yes | 3998 | 52 | 3 | - | 2022 | 2017 | yes |  |
| 32x2 | confidential signer | full+4credential-disjoint | yes | 4094 | 55 | 3 | - | 2022 | 2017 | yes |  |
| 32x2 | confidential in-proof | min | yes | 3424 | 39 | 1 | - | 2017 | 2065 | yes |  |
| 32x2 | confidential in-proof | full | yes | 3918 | 49 | 2 | 1 | 2106 | 2110 | yes |  |
| 32x2 | confidential in-proof | full+spl | yes | 4286 | 56 | 2 | - | 2238 | 2114 | no | 190 B |
| 32x2 | confidential in-proof | full+data | yes | 4118 | 49 | 2 | - | 2306 | 2306 | no | 22 B |
| 32x2 | confidential in-proof | full+reply | yes | 3918 | 49 | 2 | - | 2106 | 2110 | yes |  |
| 32x2 | confidential in-proof | full+2tree | yes | 3927 | 49 | 2 | - | 2114 | 2114 | yes |  |
| 32x2 | confidential in-proof | full+4credential-shared | yes | 3997 | 51 | 2 | - | 2118 | 2114 | yes |  |
| 32x2 | confidential in-proof | full+4credential-disjoint | yes | 4093 | 54 | 2 | - | 2118 | 2114 | yes |  |
| 32x2 | anonymous hidden | min | yes | 3496 | 39 | 1 | - | 2089 | 2167 | yes |  |
| 32x2 | anonymous hidden | full | yes | 3966 | 46 | 2 | 1 | 2250 | 2294 | yes |  |
| 32x2 | anonymous hidden | full+spl | yes | 4334 | 53 | 2 | - | 2382 | 2298 | no | 238 B |
| 32x2 | anonymous hidden | full+data | yes | 4166 | 46 | 2 | - | 2450 | 2490 | no | 70 B |
| 32x2 | anonymous hidden | full+reply | yes | 4065 | 46 | 2 | - | 2349 | 2391 | yes |  |
| 32x2 | anonymous hidden | full+2tree | yes | 3975 | 46 | 2 | - | 2258 | 2298 | yes |  |
| 32x2 | anonymous hidden | full+4credential-shared | yes | 4045 | 48 | 2 | - | 2262 | 2298 | yes |  |
| 32x2 | anonymous hidden | full+4credential-disjoint | yes | 4141 | 51 | 2 | - | 2262 | 2298 | no | 45 B |
| 32x2 | anonymous public owners | min | yes | 3433 | 39 | 1 | - | 2025 | 2070 | yes |  |
| 32x2 | anonymous public owners | full | yes | 4095 | 50 | 3 | 1 | 2186 | 2197 | yes |  |
| 32x2 | anonymous public owners | full+spl | yes | 4463 | 57 | 3 | - | 2318 | 2201 | no | 367 B |
| 32x2 | anonymous public owners | full+data | yes | 4295 | 50 | 3 | - | 2386 | 2393 | no | 199 B |
| 32x2 | anonymous public owners | full+reply | yes | 4194 | 50 | 3 | - | 2285 | 2294 | no | 98 B |
| 32x2 | anonymous public owners | full+2tree | yes | 4104 | 50 | 3 | - | 2194 | 2201 | no | 8 B |
| 32x2 | anonymous public owners | full+4credential-shared | yes | 4174 | 52 | 3 | - | 2198 | 2201 | no | 78 B |
| 32x2 | anonymous public owners | full+4credential-disjoint | yes | 4270 | 55 | 3 | - | 2198 | 2201 | no | 174 B |
| 32x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 32x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 40x2 | confidential signer | min | yes | 3849 | 47 | 1 | - | 2177 | 2232 | yes |  |
| 40x2 | confidential signer | full | yes | 4439 | 58 | 3 | none | 2266 | 2277 | no | 343 B |
| 40x2 | confidential signer | full+spl | yes | 4807 | 65 | 3 | - | 2398 | 2281 | no | 711 B, 1 accounts |
| 40x2 | confidential signer | full+data | yes | 4639 | 58 | 3 | - | 2466 | 2473 | no | 543 B |
| 40x2 | confidential signer | full+reply | yes | 4439 | 58 | 3 | - | 2266 | 2277 | no | 343 B |
| 40x2 | confidential signer | full+2tree | yes | 4449 | 58 | 3 | - | 2275 | 2281 | no | 353 B |
| 40x2 | confidential signer | full+4credential-shared | yes | 4519 | 60 | 3 | - | 2279 | 2281 | no | 423 B |
| 40x2 | confidential signer | full+4credential-disjoint | yes | 4615 | 63 | 3 | - | 2279 | 2281 | no | 519 B |
| 40x2 | confidential in-proof | min | yes | 3944 | 47 | 1 | - | 2273 | 2329 | yes |  |
| 40x2 | confidential in-proof | full | yes | 4438 | 57 | 2 | none | 2362 | 2374 | no | 342 B |
| 40x2 | confidential in-proof | full+spl | yes | 4806 | 64 | 2 | - | 2494 | 2378 | no | 710 B |
| 40x2 | confidential in-proof | full+data | yes | 4638 | 57 | 2 | - | 2562 | 2570 | no | 542 B |
| 40x2 | confidential in-proof | full+reply | yes | 4438 | 57 | 2 | - | 2362 | 2374 | no | 342 B |
| 40x2 | confidential in-proof | full+2tree | yes | 4448 | 57 | 2 | - | 2371 | 2378 | no | 352 B |
| 40x2 | confidential in-proof | full+4credential-shared | yes | 4518 | 59 | 2 | - | 2375 | 2378 | no | 422 B |
| 40x2 | confidential in-proof | full+4credential-disjoint | yes | 4614 | 62 | 2 | - | 2375 | 2378 | no | 518 B |
| 40x2 | anonymous hidden | min | yes | 4016 | 47 | 1 | - | 2345 | 2431 | yes |  |
| 40x2 | anonymous hidden | full | yes | 4486 | 54 | 2 | none | 2506 | 2558 | no | 390 B |
| 40x2 | anonymous hidden | full+spl | yes | 4854 | 61 | 2 | - | 2638 | 2562 | no | 758 B |
| 40x2 | anonymous hidden | full+data | yes | 4686 | 54 | 2 | - | 2706 | 2754 | no | 590 B |
| 40x2 | anonymous hidden | full+reply | yes | 4585 | 54 | 2 | - | 2605 | 2655 | no | 489 B |
| 40x2 | anonymous hidden | full+2tree | yes | 4496 | 54 | 2 | - | 2515 | 2562 | no | 400 B |
| 40x2 | anonymous hidden | full+4credential-shared | yes | 4566 | 56 | 2 | - | 2519 | 2562 | no | 470 B |
| 40x2 | anonymous hidden | full+4credential-disjoint | yes | 4662 | 59 | 2 | - | 2519 | 2562 | no | 566 B |
| 40x2 | anonymous public owners | min | yes | 3953 | 47 | 1 | - | 2281 | 2334 | yes |  |
| 40x2 | anonymous public owners | full | yes | 4615 | 58 | 3 | none | 2442 | 2461 | no | 519 B |
| 40x2 | anonymous public owners | full+spl | yes | 4983 | 65 | 3 | - | 2574 | 2465 | no | 887 B, 1 accounts |
| 40x2 | anonymous public owners | full+data | yes | 4815 | 58 | 3 | - | 2642 | 2657 | no | 719 B |
| 40x2 | anonymous public owners | full+reply | yes | 4714 | 58 | 3 | - | 2541 | 2558 | no | 618 B |
| 40x2 | anonymous public owners | full+2tree | yes | 4625 | 58 | 3 | - | 2451 | 2465 | no | 529 B |
| 40x2 | anonymous public owners | full+4credential-shared | yes | 4695 | 60 | 3 | - | 2455 | 2465 | no | 599 B |
| 40x2 | anonymous public owners | full+4credential-disjoint | yes | 4791 | 63 | 3 | - | 2455 | 2465 | no | 695 B |
| 40x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 40x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 48x2 | confidential signer | min | yes | 4369 | 55 | 1 | - | 2433 | 2496 | no | 273 B |
| 48x2 | confidential signer | full | yes | 4959 | 66 | 3 | none | 2522 | 2541 | no | 863 B, 2 accounts |
| 48x2 | confidential signer | full+spl | yes | 5327 | 73 | 3 | - | 2654 | 2545 | no | 1231 B, 9 accounts |
| 48x2 | confidential signer | full+data | yes | 5159 | 66 | 3 | - | 2722 | 2737 | no | 1063 B, 2 accounts |
| 48x2 | confidential signer | full+reply | yes | 4959 | 66 | 3 | - | 2522 | 2541 | no | 863 B, 2 accounts |
| 48x2 | confidential signer | full+2tree | yes | 4970 | 66 | 3 | - | 2532 | 2545 | no | 874 B, 2 accounts |
| 48x2 | confidential signer | full+4credential-shared | yes | 5040 | 68 | 3 | - | 2536 | 2545 | no | 944 B, 4 accounts |
| 48x2 | confidential signer | full+4credential-disjoint | yes | 5136 | 71 | 3 | - | 2536 | 2545 | no | 1040 B, 7 accounts |
| 48x2 | confidential in-proof | min | yes | 4464 | 55 | 1 | - | 2529 | 2593 | no | 368 B |
| 48x2 | confidential in-proof | full | yes | 4958 | 65 | 2 | none | 2618 | 2638 | no | 862 B, 1 accounts |
| 48x2 | confidential in-proof | full+spl | yes | 5326 | 72 | 2 | - | 2750 | 2642 | no | 1230 B, 8 accounts |
| 48x2 | confidential in-proof | full+data | yes | 5158 | 65 | 2 | - | 2818 | 2834 | no | 1062 B, 1 accounts |
| 48x2 | confidential in-proof | full+reply | yes | 4958 | 65 | 2 | - | 2618 | 2638 | no | 862 B, 1 accounts |
| 48x2 | confidential in-proof | full+2tree | yes | 4969 | 65 | 2 | - | 2628 | 2642 | no | 873 B, 1 accounts |
| 48x2 | confidential in-proof | full+4credential-shared | yes | 5039 | 67 | 2 | - | 2632 | 2642 | no | 943 B, 3 accounts |
| 48x2 | confidential in-proof | full+4credential-disjoint | yes | 5135 | 70 | 2 | - | 2632 | 2642 | no | 1039 B, 6 accounts |
| 48x2 | anonymous hidden | min | yes | 4536 | 55 | 1 | - | 2601 | 2695 | no | 440 B |
| 48x2 | anonymous hidden | full | yes | 5006 | 62 | 2 | none | 2762 | 2822 | no | 910 B |
| 48x2 | anonymous hidden | full+spl | yes | 5374 | 69 | 2 | - | 2894 | 2826 | no | 1278 B, 5 accounts |
| 48x2 | anonymous hidden | full+data | yes | 5206 | 62 | 2 | - | 2962 | 3018 | no | 1110 B |
| 48x2 | anonymous hidden | full+reply | yes | 5105 | 62 | 2 | - | 2861 | 2919 | no | 1009 B |
| 48x2 | anonymous hidden | full+2tree | yes | 5017 | 62 | 2 | - | 2772 | 2826 | no | 921 B |
| 48x2 | anonymous hidden | full+4credential-shared | yes | 5087 | 64 | 2 | - | 2776 | 2826 | no | 991 B |
| 48x2 | anonymous hidden | full+4credential-disjoint | yes | 5183 | 67 | 2 | - | 2776 | 2826 | no | 1087 B, 3 accounts |
| 48x2 | anonymous public owners | min | yes | 4473 | 55 | 1 | - | 2537 | 2598 | no | 377 B |
| 48x2 | anonymous public owners | full | yes | 5135 | 66 | 3 | none | 2698 | 2725 | no | 1039 B, 2 accounts |
| 48x2 | anonymous public owners | full+spl | yes | 5503 | 73 | 3 | - | 2830 | 2729 | no | 1407 B, 9 accounts |
| 48x2 | anonymous public owners | full+data | yes | 5335 | 66 | 3 | - | 2898 | 2921 | no | 1239 B, 2 accounts |
| 48x2 | anonymous public owners | full+reply | yes | 5234 | 66 | 3 | - | 2797 | 2822 | no | 1138 B, 2 accounts |
| 48x2 | anonymous public owners | full+2tree | yes | 5146 | 66 | 3 | - | 2708 | 2729 | no | 1050 B, 2 accounts |
| 48x2 | anonymous public owners | full+4credential-shared | yes | 5216 | 68 | 3 | - | 2712 | 2729 | no | 1120 B, 4 accounts |
| 48x2 | anonymous public owners | full+4credential-disjoint | yes | 5312 | 71 | 3 | - | 2712 | 2729 | no | 1216 B, 7 accounts |
| 48x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 48x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 49x2 | confidential signer | min | yes | 4434 | 56 | 1 | - | 2465 | 2529 | no | 338 B |
| 49x2 | confidential signer | full | yes | 5024 | 67 | 3 | none | 2554 | 2574 | no | 928 B, 3 accounts |
| 49x2 | confidential signer | full+spl | yes | 5392 | 74 | 3 | - | 2686 | 2578 | no | 1296 B, 10 accounts |
| 49x2 | confidential signer | full+data | yes | 5224 | 67 | 3 | - | 2754 | 2770 | no | 1128 B, 3 accounts |
| 49x2 | confidential signer | full+reply | yes | 5024 | 67 | 3 | - | 2554 | 2574 | no | 928 B, 3 accounts |
| 49x2 | confidential signer | full+2tree | yes | 5036 | 67 | 3 | - | 2565 | 2578 | no | 940 B, 3 accounts |
| 49x2 | confidential signer | full+4credential-shared | yes | 5106 | 69 | 3 | - | 2569 | 2578 | no | 1010 B, 5 accounts |
| 49x2 | confidential signer | full+4credential-disjoint | yes | 5202 | 72 | 3 | - | 2569 | 2578 | no | 1106 B, 8 accounts |
| 49x2 | confidential in-proof | min | yes | 4529 | 56 | 1 | - | 2561 | 2626 | no | 433 B |
| 49x2 | confidential in-proof | full | yes | 5023 | 66 | 2 | none | 2650 | 2671 | no | 927 B, 2 accounts |
| 49x2 | confidential in-proof | full+spl | yes | 5391 | 73 | 2 | - | 2782 | 2675 | no | 1295 B, 9 accounts |
| 49x2 | confidential in-proof | full+data | yes | 5223 | 66 | 2 | - | 2850 | 2867 | no | 1127 B, 2 accounts |
| 49x2 | confidential in-proof | full+reply | yes | 5023 | 66 | 2 | - | 2650 | 2671 | no | 927 B, 2 accounts |
| 49x2 | confidential in-proof | full+2tree | yes | 5035 | 66 | 2 | - | 2661 | 2675 | no | 939 B, 2 accounts |
| 49x2 | confidential in-proof | full+4credential-shared | yes | 5105 | 68 | 2 | - | 2665 | 2675 | no | 1009 B, 4 accounts |
| 49x2 | confidential in-proof | full+4credential-disjoint | yes | 5201 | 71 | 2 | - | 2665 | 2675 | no | 1105 B, 7 accounts |
| 49x2 | anonymous hidden | min | yes | 4601 | 56 | 1 | - | 2633 | 2728 | no | 505 B |
| 49x2 | anonymous hidden | full | yes | 5071 | 63 | 2 | none | 2794 | 2855 | no | 975 B |
| 49x2 | anonymous hidden | full+spl | yes | 5439 | 70 | 2 | - | 2926 | 2859 | no | 1343 B, 6 accounts |
| 49x2 | anonymous hidden | full+data | yes | 5271 | 63 | 2 | - | 2994 | 3051 | no | 1175 B |
| 49x2 | anonymous hidden | full+reply | yes | 5170 | 63 | 2 | - | 2893 | 2952 | no | 1074 B |
| 49x2 | anonymous hidden | full+2tree | yes | 5083 | 63 | 2 | - | 2805 | 2859 | no | 987 B |
| 49x2 | anonymous hidden | full+4credential-shared | yes | 5153 | 65 | 2 | - | 2809 | 2859 | no | 1057 B, 1 accounts |
| 49x2 | anonymous hidden | full+4credential-disjoint | yes | 5249 | 68 | 2 | - | 2809 | 2859 | no | 1153 B, 4 accounts |
| 49x2 | anonymous public owners | min | yes | 4538 | 56 | 1 | - | 2569 | 2631 | no | 442 B |
| 49x2 | anonymous public owners | full | yes | 5200 | 67 | 3 | none | 2730 | 2758 | no | 1104 B, 3 accounts |
| 49x2 | anonymous public owners | full+spl | yes | 5568 | 74 | 3 | - | 2862 | 2762 | no | 1472 B, 10 accounts |
| 49x2 | anonymous public owners | full+data | yes | 5400 | 67 | 3 | - | 2930 | 2954 | no | 1304 B, 3 accounts |
| 49x2 | anonymous public owners | full+reply | yes | 5299 | 67 | 3 | - | 2829 | 2855 | no | 1203 B, 3 accounts |
| 49x2 | anonymous public owners | full+2tree | yes | 5212 | 67 | 3 | - | 2741 | 2762 | no | 1116 B, 3 accounts |
| 49x2 | anonymous public owners | full+4credential-shared | yes | 5282 | 69 | 3 | - | 2745 | 2762 | no | 1186 B, 5 accounts |
| 49x2 | anonymous public owners | full+4credential-disjoint | yes | 5378 | 72 | 3 | - | 2745 | 2762 | no | 1282 B, 8 accounts |
| 49x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+4credential-shared | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+4credential-disjoint | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 49x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x1 | merge | ring | yes | 1603 | 15 | 1 | - | - | - | yes |  |
| 8x1 | merge | owner signed | yes | 1697 | 16 | 2 | - | - | - | yes |  |
| 24x1 | merge | ring | yes | 2643 | 31 | 1 | - | - | - | yes |  |
| 24x1 | merge | owner signed | yes | 2737 | 32 | 2 | - | - | - | yes |  |
| 52x1 | merge | ring | yes | 4463 | 59 | 1 | - | - | - | no | 367 B |
| 52x1 | merge | owner signed | yes | 4557 | 60 | 2 | - | - | - | no | 461 B |
| 0x1 | deposit | min | yes | 980 | 8 | 1 | - | - | - | yes |  |
| 0x1 | deposit | full | yes | 1251 | 14 | 2 | - | - | - | yes |  |
| 0x2 | deposit | min | yes | 1358 | 8 | 1 | - | - | - | yes |  |
| 0x2 | deposit | full | yes | 1664 | 15 | 2 | - | - | - | yes |  |
| 0x4 | deposit | min | yes | 2114 | 8 | 1 | - | - | - | yes |  |
| 0x4 | deposit | full | yes | 2490 | 17 | 2 | - | - | - | yes |  |
| 0x8 | deposit | min | yes | 3626 | 8 | 1 | - | - | - | yes |  |
| 0x8 | deposit | full | yes | 4142 | 21 | 2 | - | - | - | no | 46 B |

Entry capacities at two outputs. Each row is the widest owner run one transaction clears at that leg count, rows = run + a hidden sender. A confidential leg names its own destination, a hidden sender's legs name one. over: what stops the next owner.
| shape | rail | load | legs | leg kind | owner run | rows | accounts | signatures | frame | SPP CPI | fits | over |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 12x2 | confidential entry | min | 0 | sol | none | - | - | - | - | - | no | 341 B |
| 12x2 | confidential entry | full | 0 | sol | none | - | - | - | - | - | no | 727 B |
| 12x2 | confidential entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | 927 B |
| 12x2 | confidential entry | min | 0 | spl | none | - | - | - | - | - | no | 341 B |
| 12x2 | confidential entry | full | 0 | spl | none | - | - | - | - | - | no | 727 B |
| 12x2 | confidential entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | 927 B |
| 12x2 | anonymous entry | min | 0 | sol | none | - | - | - | - | - | no | 540 B |
| 12x2 | anonymous entry | full | 0 | sol | none | - | - | - | - | - | no | 902 B |
| 12x2 | anonymous entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | 1201 B |
| 12x2 | anonymous entry | min | 0 | spl | none | - | - | - | - | - | no | 540 B |
| 12x2 | anonymous entry | full | 0 | spl | none | - | - | - | - | - | no | 902 B |
| 12x2 | anonymous entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | 1201 B |
| 16x2 | confidential entry | min | 0 | sol | none | - | - | - | - | - | no | 1401 B |
| 16x2 | confidential entry | full | 0 | sol | none | - | - | - | - | - | no | 1787 B |
| 16x2 | confidential entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | 1987 B |
| 16x2 | confidential entry | min | 0 | spl | none | - | - | - | - | - | no | 1401 B |
| 16x2 | confidential entry | full | 0 | spl | none | - | - | - | - | - | no | 1787 B |
| 16x2 | confidential entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | 1987 B |
| 16x2 | anonymous entry | min | 0 | sol | none | - | - | - | - | - | no | 1600 B |
| 16x2 | anonymous entry | full | 0 | sol | none | - | - | - | - | - | no | 1962 B |
| 16x2 | anonymous entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | 2261 B |
| 16x2 | anonymous entry | min | 0 | spl | none | - | - | - | - | - | no | 1600 B |
| 16x2 | anonymous entry | full | 0 | spl | none | - | - | - | - | - | no | 1962 B |
| 16x2 | anonymous entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | 2261 B |
| 24x2 | confidential entry | min | 0 | sol | none | - | - | - | - | - | no | 3521 B |
| 24x2 | confidential entry | full | 0 | sol | none | - | - | - | - | - | no | 3907 B |
| 24x2 | confidential entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | 4107 B |
| 24x2 | confidential entry | min | 0 | spl | none | - | - | - | - | - | no | 3521 B |
| 24x2 | confidential entry | full | 0 | spl | none | - | - | - | - | - | no | 3907 B |
| 24x2 | confidential entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | 4107 B |
| 24x2 | anonymous entry | min | 0 | sol | none | - | - | - | - | - | no | 3720 B |
| 24x2 | anonymous entry | full | 0 | sol | none | - | - | - | - | - | no | 4082 B |
| 24x2 | anonymous entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | 4381 B |
| 24x2 | anonymous entry | min | 0 | spl | none | - | - | - | - | - | no | 3720 B |
| 24x2 | anonymous entry | full | 0 | spl | none | - | - | - | - | - | no | 4082 B |
| 24x2 | anonymous entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | 4381 B |

Maxima. Load max is full with data tails, every extension but the cache, two SPP input trees and four disjoint credential state trees, replies on anonymous frames. Each row widens one axis from that load to the largest value one transaction clears. reply: the reply length. messages: empty application messages. message bytes: one application message. over: what refuses one more step. Heap is not measured here.
| shape | rail | axis | widest | frame | SPP CPI | bytes | accounts | signatures | over |
|---|---|---|---|---|---|---|---|---|---|
| 1x2 | confidential signer | messages | 50 | 3033 | 2954 | 4082 | 24 | 3 | 20 B |
| 1x2 | confidential signer | message bytes | 1680 | 3047 | 2968 | 4096 | 24 | 3 | 1 B |
| 1x2 | confidential in-proof | messages | 50 | 3129 | 3051 | 4081 | 23 | 2 | 19 B |
| 1x2 | confidential in-proof | message bytes | 1681 | 3144 | 3066 | 4096 | 23 | 2 | 1 B |
| 1x2 | anonymous hidden | reply | 1666 | 3240 | 3201 | 4096 | 20 | 2 | 1 B |
| 1x2 | anonymous hidden | messages | 46 | 3236 | 3196 | 4092 | 20 | 2 | 30 B |
| 1x2 | anonymous hidden | message bytes | 1534 | 3240 | 3200 | 4096 | 20 | 2 | 1 B |
| 1x2 | anonymous public owners | reply | 1537 | 3047 | 2975 | 4096 | 24 | 3 | 1 B |
| 1x2 | anonymous public owners | messages | 42 | 3036 | 2963 | 4085 | 24 | 3 | 23 B |
| 1x2 | anonymous public owners | message bytes | 1405 | 3047 | 2974 | 4096 | 24 | 3 | 1 B |
| 1x2 | confidential entry | messages | 44 | 3037 | 2958 | 4086 | 24 | 3 | 24 B |
| 1x2 | confidential entry | message bytes | 1472 | 3047 | 2968 | 4096 | 24 | 3 | 1 B |
| 1x2 | anonymous entry | reply | 1426 | 3240 | 3169 | 4096 | 20 | 2 | 1 B |
| 1x2 | anonymous entry | messages | 39 | 3238 | 3166 | 4094 | 20 | 2 | 32 B |
| 1x2 | anonymous entry | message bytes | 1294 | 3240 | 3168 | 4096 | 20 | 2 | 1 B |
| 1x4 | confidential signer | messages | 31 | 3019 | 3008 | 4068 | 24 | 3 | 6 B |
| 1x4 | confidential signer | message bytes | 1048 | 3047 | 3036 | 4096 | 24 | 3 | 1 B |
| 1x4 | confidential in-proof | messages | 31 | 3115 | 3105 | 4067 | 23 | 2 | 5 B |
| 1x4 | confidential in-proof | message bytes | 1049 | 3144 | 3134 | 4096 | 23 | 2 | 1 B |
| 1x4 | anonymous hidden | reply | 323 | 3239 | 3268 | 4095 | 20 | 2 | 2 B |
| 1x4 | anonymous hidden | messages | 19 | 3208 | 3236 | 4064 | 20 | 2 | 2 B |
| 1x4 | anonymous hidden | message bytes | 644 | 3240 | 3268 | 4096 | 20 | 2 | 1 B |
| 1x4 | anonymous public owners | reply | 280 | 3046 | 3042 | 4095 | 24 | 3 | 2 B |
| 1x4 | anonymous public owners | messages | 16 | 3042 | 3037 | 4091 | 24 | 3 | 29 B |
| 1x4 | anonymous public owners | message bytes | 515 | 3047 | 3042 | 4096 | 24 | 3 | 1 B |
| 1x4 | confidential entry | messages | 25 | 3023 | 3012 | 4072 | 24 | 3 | 10 B |
| 1x4 | confidential entry | message bytes | 840 | 3047 | 3036 | 4096 | 24 | 3 | 1 B |
| 1x4 | anonymous entry | reply | 243 | 3239 | 3236 | 4095 | 20 | 2 | 2 B |
| 1x4 | anonymous entry | messages | 12 | 3210 | 3206 | 4066 | 20 | 2 | 4 B |
| 1x4 | anonymous entry | message bytes | 404 | 3240 | 3236 | 4096 | 20 | 2 | 1 B |
| 1x8 | confidential signer | messages | none | - | - | - | - | - | 181 B |
| 1x8 | confidential signer | message bytes | none | - | - | - | - | - | 216 B |
| 1x8 | confidential in-proof | messages | none | - | - | - | - | - | 180 B |
| 1x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 215 B |
| 1x8 | anonymous hidden | reply | none | - | - | - | - | - | 1101 B |
| 1x8 | anonymous hidden | messages | none | - | - | - | - | - | 1101 B |
| 1x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1136 B |
| 1x8 | anonymous public owners | reply | none | - | - | - | - | - | 1230 B |
| 1x8 | anonymous public owners | messages | none | - | - | - | - | - | 1230 B |
| 1x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1265 B |
| 1x8 | confidential entry | messages | none | - | - | - | - | - | 389 B |
| 1x8 | confidential entry | message bytes | none | - | - | - | - | - | 424 B |
| 1x8 | anonymous entry | reply | none | - | - | - | - | - | 1341 B |
| 1x8 | anonymous entry | messages | none | - | - | - | - | - | 1341 B |
| 1x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1376 B |
| 2x2 | confidential signer | messages | 48 | 2997 | 2919 | 4079 | 25 | 3 | 17 B |
| 2x2 | confidential signer | message bytes | 1615 | 3014 | 2936 | 4096 | 25 | 3 | 1 B |
| 2x2 | confidential in-proof | messages | 48 | 3093 | 3016 | 4078 | 24 | 2 | 16 B |
| 2x2 | confidential in-proof | message bytes | 1616 | 3111 | 3034 | 4096 | 24 | 2 | 1 B |
| 2x2 | anonymous hidden | reply | 1601 | 3207 | 3169 | 4096 | 21 | 2 | 1 B |
| 2x2 | anonymous hidden | messages | 44 | 3200 | 3161 | 4089 | 21 | 2 | 27 B |
| 2x2 | anonymous hidden | message bytes | 1469 | 3207 | 3168 | 4096 | 21 | 2 | 1 B |
| 2x2 | anonymous public owners | reply | 1472 | 3014 | 2943 | 4096 | 25 | 3 | 1 B |
| 2x2 | anonymous public owners | messages | 40 | 3000 | 2928 | 4082 | 25 | 3 | 20 B |
| 2x2 | anonymous public owners | message bytes | 1340 | 3014 | 2942 | 4096 | 25 | 3 | 1 B |
| 2x2 | confidential entry | messages | 36 | 2997 | 2919 | 4079 | 25 | 3 | 17 B |
| 2x2 | confidential entry | message bytes | 1207 | 3014 | 2936 | 4096 | 25 | 3 | 1 B |
| 2x2 | anonymous entry | reply | 1161 | 3207 | 3137 | 4096 | 21 | 2 | 1 B |
| 2x2 | anonymous entry | messages | 31 | 3198 | 3127 | 4087 | 21 | 2 | 25 B |
| 2x2 | anonymous entry | message bytes | 1029 | 3207 | 3136 | 4096 | 21 | 2 | 1 B |
| 2x2 | delegate | messages | 55 | 3179 | 3157 | 4065 | 21 | 2 | 3 B |
| 2x2 | delegate | message bytes | 1867 | 3210 | 3188 | 4096 | 21 | 2 | 1 B |
| 2x2 | anonymous delegate | reply | 1724 | 3210 | 3195 | 4096 | 21 | 2 | 1 B |
| 2x2 | anonymous delegate | messages | 47 | 3182 | 3166 | 4068 | 21 | 2 | 6 B |
| 2x2 | anonymous delegate | message bytes | 1592 | 3210 | 3194 | 4096 | 21 | 2 | 1 B |
| 2x4 | confidential signer | messages | 29 | 2983 | 2973 | 4065 | 25 | 3 | 3 B |
| 2x4 | confidential signer | message bytes | 983 | 3014 | 3004 | 4096 | 25 | 3 | 1 B |
| 2x4 | confidential in-proof | messages | 29 | 3079 | 3070 | 4064 | 24 | 2 | 2 B |
| 2x4 | confidential in-proof | message bytes | 984 | 3111 | 3102 | 4096 | 24 | 2 | 1 B |
| 2x4 | anonymous hidden | reply | 301 | 3205 | 3235 | 4094 | 21 | 2 | 1 B |
| 2x4 | anonymous hidden | messages | 18 | 3206 | 3235 | 4095 | 21 | 2 | 33 B |
| 2x4 | anonymous hidden | message bytes | 579 | 3207 | 3236 | 4096 | 21 | 2 | 1 B |
| 2x4 | anonymous public owners | reply | 258 | 3012 | 3009 | 4094 | 25 | 3 | 1 B |
| 2x4 | anonymous public owners | messages | 14 | 3006 | 3002 | 4088 | 25 | 3 | 26 B |
| 2x4 | anonymous public owners | message bytes | 450 | 3014 | 3010 | 4096 | 25 | 3 | 1 B |
| 2x4 | confidential entry | messages | 17 | 2983 | 2973 | 4065 | 25 | 3 | 3 B |
| 2x4 | confidential entry | message bytes | 575 | 3014 | 3004 | 4096 | 25 | 3 | 1 B |
| 2x4 | anonymous entry | reply | 155 | 3207 | 3205 | 4096 | 21 | 2 | 3 B |
| 2x4 | anonymous entry | messages | 5 | 3204 | 3201 | 4093 | 21 | 2 | 31 B |
| 2x4 | anonymous entry | message bytes | 139 | 3207 | 3204 | 4096 | 21 | 2 | 1 B |
| 1x16 | confidential signer | messages | none | - | - | - | - | - | 2711 B |
| 1x16 | confidential signer | message bytes | none | - | - | - | - | - | 2746 B |
| 1x16 | confidential in-proof | messages | none | - | - | - | - | - | 2710 B |
| 1x16 | confidential in-proof | message bytes | none | - | - | - | - | - | 2745 B |
| 1x16 | anonymous hidden | reply | none | - | - | - | - | - | 4663 B |
| 1x16 | anonymous hidden | messages | none | - | - | - | - | - | 4663 B |
| 1x16 | anonymous hidden | message bytes | none | - | - | - | - | - | 4698 B |
| 1x16 | anonymous public owners | reply | none | - | - | - | - | - | 4792 B |
| 1x16 | anonymous public owners | messages | none | - | - | - | - | - | 4792 B |
| 1x16 | anonymous public owners | message bytes | none | - | - | - | - | - | 4827 B |
| 2x8 | confidential signer | messages | none | - | - | - | - | - | 246 B |
| 2x8 | confidential signer | message bytes | none | - | - | - | - | - | 281 B |
| 2x8 | confidential in-proof | messages | none | - | - | - | - | - | 245 B |
| 2x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 280 B |
| 2x8 | anonymous hidden | reply | none | - | - | - | - | - | 1166 B |
| 2x8 | anonymous hidden | messages | none | - | - | - | - | - | 1166 B |
| 2x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1201 B |
| 2x8 | anonymous public owners | reply | none | - | - | - | - | - | 1295 B |
| 2x8 | anonymous public owners | messages | none | - | - | - | - | - | 1295 B |
| 2x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1330 B |
| 2x8 | confidential entry | messages | none | - | - | - | - | - | 654 B |
| 2x8 | confidential entry | message bytes | none | - | - | - | - | - | 689 B |
| 2x8 | anonymous entry | reply | none | - | - | - | - | - | 1606 B |
| 2x8 | anonymous entry | messages | none | - | - | - | - | - | 1606 B |
| 2x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1641 B |
| 3x2 | confidential signer | messages | 46 | 2961 | 2884 | 4076 | 26 | 3 | 14 B |
| 3x2 | confidential signer | message bytes | 1550 | 2981 | 2904 | 4096 | 26 | 3 | 1 B |
| 3x2 | confidential in-proof | messages | 46 | 3057 | 2981 | 4075 | 25 | 2 | 13 B |
| 3x2 | confidential in-proof | message bytes | 1551 | 3078 | 3002 | 4096 | 25 | 2 | 1 B |
| 3x2 | anonymous hidden | reply | 1536 | 3174 | 3137 | 4096 | 22 | 2 | 1 B |
| 3x2 | anonymous hidden | messages | 42 | 3164 | 3126 | 4086 | 22 | 2 | 24 B |
| 3x2 | anonymous hidden | message bytes | 1404 | 3174 | 3136 | 4096 | 22 | 2 | 1 B |
| 3x2 | anonymous public owners | reply | 1407 | 2981 | 2911 | 4096 | 26 | 3 | 1 B |
| 3x2 | anonymous public owners | messages | 38 | 2964 | 2893 | 4079 | 26 | 3 | 17 B |
| 3x2 | anonymous public owners | message bytes | 1275 | 2981 | 2910 | 4096 | 26 | 3 | 1 B |
| 3x2 | confidential entry | messages | 28 | 2957 | 2880 | 4072 | 26 | 3 | 10 B |
| 3x2 | confidential entry | message bytes | 942 | 2981 | 2904 | 4096 | 26 | 3 | 1 B |
| 3x2 | anonymous entry | reply | 896 | 3174 | 3105 | 4096 | 22 | 2 | 1 B |
| 3x2 | anonymous entry | messages | 23 | 3158 | 3088 | 4080 | 22 | 2 | 18 B |
| 3x2 | anonymous entry | message bytes | 764 | 3174 | 3104 | 4096 | 22 | 2 | 1 B |
| 3x4 | confidential signer | messages | 28 | 2981 | 2972 | 4096 | 26 | 3 | 34 B |
| 3x4 | confidential signer | message bytes | 918 | 2981 | 2972 | 4096 | 26 | 3 | 1 B |
| 3x4 | confidential in-proof | messages | 28 | 3077 | 3069 | 4095 | 25 | 2 | 33 B |
| 3x4 | confidential in-proof | message bytes | 919 | 3078 | 3070 | 4096 | 25 | 2 | 1 B |
| 3x4 | anonymous hidden | reply | 280 | 3174 | 3205 | 4096 | 22 | 2 | 3 B |
| 3x4 | anonymous hidden | messages | 16 | 3170 | 3200 | 4092 | 22 | 2 | 30 B |
| 3x4 | anonymous hidden | message bytes | 514 | 3174 | 3204 | 4096 | 22 | 2 | 1 B |
| 3x4 | anonymous public owners | reply | 237 | 2981 | 2979 | 4096 | 26 | 3 | 3 B |
| 3x4 | anonymous public owners | messages | 12 | 2970 | 2967 | 4085 | 26 | 3 | 23 B |
| 3x4 | anonymous public owners | message bytes | 385 | 2981 | 2978 | 4096 | 26 | 3 | 1 B |
| 3x4 | confidential entry | messages | 10 | 2977 | 2968 | 4092 | 26 | 3 | 30 B |
| 3x4 | confidential entry | message bytes | 310 | 2981 | 2972 | 4096 | 26 | 3 | 1 B |
| 3x4 | anonymous entry | reply | none | - | - | - | - | - | 91 B |
| 3x4 | anonymous entry | messages | none | - | - | - | - | - | 91 B |
| 3x4 | anonymous entry | message bytes | none | - | - | - | - | - | 126 B |
| 2x16 | confidential signer | messages | none | - | - | - | - | - | 2776 B |
| 2x16 | confidential signer | message bytes | none | - | - | - | - | - | 2811 B |
| 2x16 | confidential in-proof | messages | none | - | - | - | - | - | 2775 B |
| 2x16 | confidential in-proof | message bytes | none | - | - | - | - | - | 2810 B |
| 2x16 | anonymous hidden | reply | none | - | - | - | - | - | 4728 B |
| 2x16 | anonymous hidden | messages | none | - | - | - | - | - | 4728 B |
| 2x16 | anonymous hidden | message bytes | none | - | - | - | - | - | 4763 B |
| 2x16 | anonymous public owners | reply | none | - | - | - | - | - | 4857 B |
| 2x16 | anonymous public owners | messages | none | - | - | - | - | - | 4857 B |
| 2x16 | anonymous public owners | message bytes | none | - | - | - | - | - | 4892 B |
| 3x8 | confidential signer | messages | none | - | - | - | - | - | 311 B |
| 3x8 | confidential signer | message bytes | none | - | - | - | - | - | 346 B |
| 3x8 | confidential in-proof | messages | none | - | - | - | - | - | 310 B |
| 3x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 345 B |
| 3x8 | anonymous hidden | reply | none | - | - | - | - | - | 1231 B |
| 3x8 | anonymous hidden | messages | none | - | - | - | - | - | 1231 B |
| 3x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1266 B |
| 3x8 | anonymous public owners | reply | none | - | - | - | - | - | 1360 B |
| 3x8 | anonymous public owners | messages | none | - | - | - | - | - | 1360 B |
| 3x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1395 B |
| 3x8 | confidential entry | messages | none | - | - | - | - | - | 919 B |
| 3x8 | confidential entry | message bytes | none | - | - | - | - | - | 954 B |
| 3x8 | anonymous entry | reply | none | - | - | - | - | - | 1871 B |
| 3x8 | anonymous entry | messages | none | - | - | - | - | - | 1871 B |
| 3x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1906 B |
| 4x2 | confidential signer | messages | 44 | 2925 | 2849 | 4073 | 27 | 3 | 11 B |
| 4x2 | confidential signer | message bytes | 1485 | 2948 | 2872 | 4096 | 27 | 3 | 1 B |
| 4x2 | confidential in-proof | messages | 44 | 3021 | 2946 | 4072 | 26 | 2 | 10 B |
| 4x2 | confidential in-proof | message bytes | 1486 | 3045 | 2970 | 4096 | 26 | 2 | 1 B |
| 4x2 | anonymous hidden | reply | 1471 | 3141 | 3105 | 4096 | 23 | 2 | 1 B |
| 4x2 | anonymous hidden | messages | 40 | 3128 | 3091 | 4083 | 23 | 2 | 21 B |
| 4x2 | anonymous hidden | message bytes | 1339 | 3141 | 3104 | 4096 | 23 | 2 | 1 B |
| 4x2 | anonymous public owners | reply | 1342 | 2948 | 2879 | 4096 | 27 | 3 | 1 B |
| 4x2 | anonymous public owners | messages | 36 | 2928 | 2858 | 4076 | 27 | 3 | 14 B |
| 4x2 | anonymous public owners | message bytes | 1210 | 2948 | 2878 | 4096 | 27 | 3 | 1 B |
| 4x2 | confidential entry | messages | 20 | 2917 | 2841 | 4065 | 27 | 3 | 3 B |
| 4x2 | confidential entry | message bytes | 677 | 2948 | 2872 | 4096 | 27 | 3 | 1 B |
| 4x2 | anonymous entry | reply | 631 | 3141 | 3073 | 4096 | 23 | 2 | 1 B |
| 4x2 | anonymous entry | messages | 15 | 3118 | 3049 | 4073 | 23 | 2 | 11 B |
| 4x2 | anonymous entry | message bytes | 499 | 3141 | 3072 | 4096 | 23 | 2 | 1 B |
| 4x4 | confidential signer | messages | 26 | 2945 | 2937 | 4093 | 27 | 3 | 31 B |
| 4x4 | confidential signer | message bytes | 853 | 2948 | 2940 | 4096 | 27 | 3 | 1 B |
| 4x4 | confidential in-proof | messages | 26 | 3041 | 3034 | 4092 | 26 | 2 | 30 B |
| 4x4 | confidential in-proof | message bytes | 854 | 3045 | 3038 | 4096 | 26 | 2 | 1 B |
| 4x4 | anonymous hidden | reply | 258 | 3140 | 3172 | 4095 | 23 | 2 | 2 B |
| 4x4 | anonymous hidden | messages | 14 | 3134 | 3165 | 4089 | 23 | 2 | 27 B |
| 4x4 | anonymous hidden | message bytes | 449 | 3141 | 3172 | 4096 | 23 | 2 | 1 B |
| 4x4 | anonymous public owners | reply | 215 | 2947 | 2946 | 4095 | 27 | 3 | 2 B |
| 4x4 | anonymous public owners | messages | 10 | 2934 | 2932 | 4082 | 27 | 3 | 20 B |
| 4x4 | anonymous public owners | message bytes | 320 | 2948 | 2946 | 4096 | 27 | 3 | 1 B |
| 4x4 | confidential entry | messages | 2 | 2937 | 2929 | 4085 | 27 | 3 | 23 B |
| 4x4 | confidential entry | message bytes | 45 | 2948 | 2940 | 4096 | 27 | 3 | 1 B |
| 4x4 | anonymous entry | reply | none | - | - | - | - | - | 356 B |
| 4x4 | anonymous entry | messages | none | - | - | - | - | - | 356 B |
| 4x4 | anonymous entry | message bytes | none | - | - | - | - | - | 391 B |
| 4x4 | delegate | messages | 33 | 3127 | 3175 | 4079 | 23 | 2 | 17 B |
| 4x4 | delegate | message bytes | 1105 | 3144 | 3192 | 4096 | 23 | 2 | 1 B |
| 4x4 | anonymous delegate | reply | 299 | 3143 | 3198 | 4095 | 23 | 2 | 2 B |
| 4x4 | anonymous delegate | messages | 17 | 3116 | 3170 | 4068 | 23 | 2 | 6 B |
| 4x4 | anonymous delegate | message bytes | 572 | 3144 | 3198 | 4096 | 23 | 2 | 1 B |
| 4x8 | confidential signer | messages | none | - | - | - | - | - | 376 B |
| 4x8 | confidential signer | message bytes | none | - | - | - | - | - | 411 B |
| 4x8 | confidential in-proof | messages | none | - | - | - | - | - | 375 B |
| 4x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 410 B |
| 4x8 | anonymous hidden | reply | none | - | - | - | - | - | 1296 B |
| 4x8 | anonymous hidden | messages | none | - | - | - | - | - | 1296 B |
| 4x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1331 B |
| 4x8 | anonymous public owners | reply | none | - | - | - | - | - | 1425 B |
| 4x8 | anonymous public owners | messages | none | - | - | - | - | - | 1425 B |
| 4x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1460 B |
| 4x8 | confidential entry | messages | none | - | - | - | - | - | 1184 B |
| 4x8 | confidential entry | message bytes | none | - | - | - | - | - | 1219 B |
| 4x8 | anonymous entry | reply | none | - | - | - | - | - | 2136 B |
| 4x8 | anonymous entry | messages | none | - | - | - | - | - | 2136 B |
| 4x8 | anonymous entry | message bytes | none | - | - | - | - | - | 2171 B |
| 5x2 | confidential signer | messages | 42 | 2889 | 2814 | 4070 | 28 | 3 | 8 B |
| 5x2 | confidential signer | message bytes | 1420 | 2915 | 2840 | 4096 | 28 | 3 | 1 B |
| 5x2 | confidential in-proof | messages | 42 | 2985 | 2911 | 4069 | 27 | 2 | 7 B |
| 5x2 | confidential in-proof | message bytes | 1421 | 3012 | 2938 | 4096 | 27 | 2 | 1 B |
| 5x2 | anonymous hidden | reply | 1406 | 3108 | 3073 | 4096 | 24 | 2 | 1 B |
| 5x2 | anonymous hidden | messages | 38 | 3092 | 3056 | 4080 | 24 | 2 | 18 B |
| 5x2 | anonymous hidden | message bytes | 1274 | 3108 | 3072 | 4096 | 24 | 2 | 1 B |
| 5x2 | anonymous public owners | reply | 1277 | 2915 | 2847 | 4096 | 28 | 3 | 1 B |
| 5x2 | anonymous public owners | messages | 34 | 2892 | 2823 | 4073 | 28 | 3 | 11 B |
| 5x2 | anonymous public owners | message bytes | 1145 | 2915 | 2846 | 4096 | 28 | 3 | 1 B |
| 5x2 | confidential entry | messages | 13 | 2911 | 2836 | 4092 | 28 | 3 | 30 B |
| 5x2 | confidential entry | message bytes | 412 | 2915 | 2840 | 4096 | 28 | 3 | 1 B |
| 5x2 | anonymous entry | reply | 366 | 3108 | 3041 | 4096 | 24 | 2 | 1 B |
| 5x2 | anonymous entry | messages | 7 | 3078 | 3010 | 4066 | 24 | 2 | 4 B |
| 5x2 | anonymous entry | message bytes | 234 | 3108 | 3040 | 4096 | 24 | 2 | 1 B |
| 5x4 | confidential signer | messages | 24 | 2909 | 2902 | 4090 | 28 | 3 | 28 B |
| 5x4 | confidential signer | message bytes | 788 | 2915 | 2908 | 4096 | 28 | 3 | 1 B |
| 5x4 | confidential in-proof | messages | 24 | 3005 | 2999 | 4089 | 27 | 2 | 27 B |
| 5x4 | confidential in-proof | message bytes | 789 | 3012 | 3006 | 4096 | 27 | 2 | 1 B |
| 5x4 | anonymous hidden | reply | 236 | 3106 | 3139 | 4094 | 24 | 2 | 1 B |
| 5x4 | anonymous hidden | messages | 12 | 3098 | 3130 | 4086 | 24 | 2 | 24 B |
| 5x4 | anonymous hidden | message bytes | 384 | 3108 | 3140 | 4096 | 24 | 2 | 1 B |
| 5x4 | anonymous public owners | reply | 193 | 2913 | 2913 | 4094 | 28 | 3 | 1 B |
| 5x4 | anonymous public owners | messages | 8 | 2898 | 2897 | 4079 | 28 | 3 | 17 B |
| 5x4 | anonymous public owners | message bytes | 255 | 2915 | 2914 | 4096 | 28 | 3 | 1 B |
| 5x4 | confidential entry | messages | none | - | - | - | - | - | 185 B |
| 5x4 | confidential entry | message bytes | none | - | - | - | - | - | 220 B |
| 5x4 | anonymous entry | reply | none | - | - | - | - | - | 621 B |
| 5x4 | anonymous entry | messages | none | - | - | - | - | - | 621 B |
| 5x4 | anonymous entry | message bytes | none | - | - | - | - | - | 656 B |
| 4x16 | confidential signer | messages | none | - | - | - | - | - | 2906 B |
| 4x16 | confidential signer | message bytes | none | - | - | - | - | - | 2941 B |
| 4x16 | confidential in-proof | messages | none | - | - | - | - | - | 2905 B |
| 4x16 | confidential in-proof | message bytes | none | - | - | - | - | - | 2940 B |
| 4x16 | anonymous hidden | reply | none | - | - | - | - | - | 4858 B |
| 4x16 | anonymous hidden | messages | none | - | - | - | - | - | 4858 B |
| 4x16 | anonymous hidden | message bytes | none | - | - | - | - | - | 4893 B |
| 4x16 | anonymous public owners | reply | none | - | - | - | - | - | 4987 B |
| 4x16 | anonymous public owners | messages | none | - | - | - | - | - | 4987 B |
| 4x16 | anonymous public owners | message bytes | none | - | - | - | - | - | 5022 B |
| 5x8 | confidential signer | messages | none | - | - | - | - | - | 441 B |
| 5x8 | confidential signer | message bytes | none | - | - | - | - | - | 476 B |
| 5x8 | confidential in-proof | messages | none | - | - | - | - | - | 440 B |
| 5x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 475 B |
| 5x8 | anonymous hidden | reply | none | - | - | - | - | - | 1361 B |
| 5x8 | anonymous hidden | messages | none | - | - | - | - | - | 1361 B |
| 5x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1396 B |
| 5x8 | anonymous public owners | reply | none | - | - | - | - | - | 1490 B |
| 5x8 | anonymous public owners | messages | none | - | - | - | - | - | 1490 B |
| 5x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1525 B |
| 6x2 | confidential signer | messages | 40 | 2853 | 2779 | 4067 | 29 | 3 | 5 B |
| 6x2 | confidential signer | message bytes | 1355 | 2882 | 2808 | 4096 | 29 | 3 | 1 B |
| 6x2 | confidential in-proof | messages | 40 | 2949 | 2876 | 4066 | 28 | 2 | 4 B |
| 6x2 | confidential in-proof | message bytes | 1356 | 2979 | 2906 | 4096 | 28 | 2 | 1 B |
| 6x2 | anonymous hidden | reply | 1341 | 3075 | 3041 | 4096 | 25 | 2 | 1 B |
| 6x2 | anonymous hidden | messages | 36 | 3056 | 3021 | 4077 | 25 | 2 | 15 B |
| 6x2 | anonymous hidden | message bytes | 1209 | 3075 | 3040 | 4096 | 25 | 2 | 1 B |
| 6x2 | anonymous public owners | reply | 1212 | 2882 | 2815 | 4096 | 29 | 3 | 1 B |
| 6x2 | anonymous public owners | messages | 32 | 2856 | 2788 | 4070 | 29 | 3 | 8 B |
| 6x2 | anonymous public owners | message bytes | 1080 | 2882 | 2814 | 4096 | 29 | 3 | 1 B |
| 6x2 | confidential entry | messages | 5 | 2871 | 2797 | 4085 | 29 | 3 | 23 B |
| 6x2 | confidential entry | message bytes | 147 | 2882 | 2808 | 4096 | 29 | 3 | 1 B |
| 6x2 | anonymous entry | reply | 101 | 3075 | 3009 | 4096 | 25 | 2 | 1 B |
| 6x2 | anonymous entry | messages | 0 | 3071 | 3005 | 4092 | 25 | 2 | 31 B |
| 6x2 | anonymous entry | message bytes | none | - | - | - | - | - | 31 B |
| 6x4 | confidential signer | messages | 22 | 2873 | 2867 | 4087 | 29 | 3 | 25 B |
| 6x4 | confidential signer | message bytes | 723 | 2882 | 2876 | 4096 | 29 | 3 | 1 B |
| 6x4 | confidential in-proof | messages | 22 | 2969 | 2964 | 4086 | 28 | 2 | 24 B |
| 6x4 | confidential in-proof | message bytes | 724 | 2979 | 2974 | 4096 | 28 | 2 | 1 B |
| 6x4 | anonymous hidden | reply | 215 | 3075 | 3109 | 4096 | 25 | 2 | 3 B |
| 6x4 | anonymous hidden | messages | 10 | 3062 | 3095 | 4083 | 25 | 2 | 21 B |
| 6x4 | anonymous hidden | message bytes | 319 | 3075 | 3108 | 4096 | 25 | 2 | 1 B |
| 6x4 | anonymous public owners | reply | 172 | 2882 | 2883 | 4096 | 29 | 3 | 3 B |
| 6x4 | anonymous public owners | messages | 6 | 2862 | 2862 | 4076 | 29 | 3 | 14 B |
| 6x4 | anonymous public owners | message bytes | 190 | 2882 | 2882 | 4096 | 29 | 3 | 1 B |
| 6x4 | confidential entry | messages | none | - | - | - | - | - | 450 B |
| 6x4 | confidential entry | message bytes | none | - | - | - | - | - | 485 B |
| 6x4 | anonymous entry | reply | none | - | - | - | - | - | 886 B |
| 6x4 | anonymous entry | messages | none | - | - | - | - | - | 886 B |
| 6x4 | anonymous entry | message bytes | none | - | - | - | - | - | 921 B |
| 5x16 | confidential signer | messages | none | - | - | - | - | - | 2971 B |
| 5x16 | confidential signer | message bytes | none | - | - | - | - | - | 3006 B |
| 5x16 | confidential in-proof | messages | none | - | - | - | - | - | 2970 B |
| 5x16 | confidential in-proof | message bytes | none | - | - | - | - | - | 3005 B |
| 5x16 | anonymous hidden | reply | none | - | - | - | - | - | 4923 B |
| 5x16 | anonymous hidden | messages | none | - | - | - | - | - | 4923 B |
| 5x16 | anonymous hidden | message bytes | none | - | - | - | - | - | 4958 B |
| 5x16 | anonymous public owners | reply | none | - | - | - | - | - | 5052 B |
| 5x16 | anonymous public owners | messages | none | - | - | - | - | - | 5052 B |
| 5x16 | anonymous public owners | message bytes | none | - | - | - | - | - | 5087 B |
| 6x8 | confidential signer | messages | none | - | - | - | - | - | 506 B |
| 6x8 | confidential signer | message bytes | none | - | - | - | - | - | 541 B |
| 6x8 | confidential in-proof | messages | none | - | - | - | - | - | 505 B |
| 6x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 540 B |
| 6x8 | anonymous hidden | reply | none | - | - | - | - | - | 1426 B |
| 6x8 | anonymous hidden | messages | none | - | - | - | - | - | 1426 B |
| 6x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1461 B |
| 6x8 | anonymous public owners | reply | none | - | - | - | - | - | 1555 B |
| 6x8 | anonymous public owners | messages | none | - | - | - | - | - | 1555 B |
| 6x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1590 B |
| 8x2 | confidential signer | messages | 37 | 2815 | 2743 | 4095 | 31 | 3 | 33 B |
| 8x2 | confidential signer | message bytes | 1225 | 2816 | 2744 | 4096 | 31 | 3 | 1 B |
| 8x2 | confidential in-proof | messages | 37 | 2911 | 2840 | 4094 | 30 | 2 | 32 B |
| 8x2 | confidential in-proof | message bytes | 1226 | 2913 | 2842 | 4096 | 30 | 2 | 1 B |
| 8x2 | anonymous hidden | reply | 1211 | 3009 | 2977 | 4096 | 27 | 2 | 1 B |
| 8x2 | anonymous hidden | messages | 32 | 2984 | 2951 | 4071 | 27 | 2 | 9 B |
| 8x2 | anonymous hidden | message bytes | 1079 | 3009 | 2976 | 4096 | 27 | 2 | 1 B |
| 8x2 | anonymous public owners | reply | 1082 | 2816 | 2751 | 4096 | 31 | 3 | 1 B |
| 8x2 | anonymous public owners | messages | 28 | 2784 | 2718 | 4064 | 31 | 3 | 2 B |
| 8x2 | anonymous public owners | message bytes | 950 | 2816 | 2750 | 4096 | 31 | 3 | 1 B |
| 8x2 | confidential entry | messages | none | - | - | - | - | - | 348 B |
| 8x2 | confidential entry | message bytes | none | - | - | - | - | - | 383 B |
| 8x2 | anonymous entry | reply | none | - | - | - | - | - | 526 B |
| 8x2 | anonymous entry | messages | none | - | - | - | - | - | 526 B |
| 8x2 | anonymous entry | message bytes | none | - | - | - | - | - | 561 B |
| 8x4 | confidential signer | messages | 18 | 2801 | 2797 | 4081 | 31 | 3 | 19 B |
| 8x4 | confidential signer | message bytes | 593 | 2816 | 2812 | 4096 | 31 | 3 | 1 B |
| 8x4 | confidential in-proof | messages | 18 | 2897 | 2894 | 4080 | 30 | 2 | 18 B |
| 8x4 | confidential in-proof | message bytes | 594 | 2913 | 2910 | 4096 | 30 | 2 | 1 B |
| 8x4 | anonymous hidden | reply | 171 | 3007 | 3043 | 4094 | 27 | 2 | 1 B |
| 8x4 | anonymous hidden | messages | 6 | 2990 | 3025 | 4077 | 27 | 2 | 15 B |
| 8x4 | anonymous hidden | message bytes | 189 | 3009 | 3044 | 4096 | 27 | 2 | 1 B |
| 8x4 | anonymous public owners | reply | 128 | 2814 | 2817 | 4094 | 31 | 3 | 1 B |
| 8x4 | anonymous public owners | messages | 2 | 2790 | 2792 | 4070 | 31 | 3 | 8 B |
| 8x4 | anonymous public owners | message bytes | 60 | 2816 | 2818 | 4096 | 31 | 3 | 1 B |
| 8x4 | confidential entry | messages | none | - | - | - | - | - | 980 B |
| 8x4 | confidential entry | message bytes | none | - | - | - | - | - | 1015 B |
| 8x4 | anonymous entry | reply | none | - | - | - | - | - | 1416 B |
| 8x4 | anonymous entry | messages | none | - | - | - | - | - | 1416 B |
| 8x4 | anonymous entry | message bytes | none | - | - | - | - | - | 1451 B |
| 8x8 | confidential signer | messages | none | - | - | - | - | - | 636 B |
| 8x8 | confidential signer | message bytes | none | - | - | - | - | - | 671 B |
| 8x8 | confidential in-proof | messages | none | - | - | - | - | - | 635 B |
| 8x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 670 B |
| 8x8 | anonymous hidden | reply | none | - | - | - | - | - | 1556 B |
| 8x8 | anonymous hidden | messages | none | - | - | - | - | - | 1556 B |
| 8x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1591 B |
| 8x8 | anonymous public owners | reply | none | - | - | - | - | - | 1685 B |
| 8x8 | anonymous public owners | messages | none | - | - | - | - | - | 1685 B |
| 8x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1720 B |
| 8x16 | confidential signer | messages | none | - | - | - | - | - | 3166 B |
| 8x16 | confidential signer | message bytes | none | - | - | - | - | - | 3201 B |
| 8x16 | confidential in-proof | messages | none | - | - | - | - | - | 3165 B |
| 8x16 | confidential in-proof | message bytes | none | - | - | - | - | - | 3200 B |
| 8x16 | anonymous hidden | reply | none | - | - | - | - | - | 5118 B |
| 8x16 | anonymous hidden | messages | none | - | - | - | - | - | 5118 B |
| 8x16 | anonymous hidden | message bytes | none | - | - | - | - | - | 5153 B |
| 8x16 | anonymous public owners | reply | none | - | - | - | - | - | 5247 B |
| 8x16 | anonymous public owners | messages | none | - | - | - | - | - | 5247 B |
| 8x16 | anonymous public owners | message bytes | none | - | - | - | - | - | 5282 B |
| 12x2 | confidential signer | messages | 29 | 2672 | 2603 | 4084 | 35 | 3 | 22 B |
| 12x2 | confidential signer | message bytes | 964 | 2684 | 2615 | 4096 | 35 | 3 | 1 B |
| 12x2 | confidential in-proof | messages | 29 | 2768 | 2700 | 4083 | 34 | 2 | 21 B |
| 12x2 | confidential in-proof | message bytes | 965 | 2781 | 2713 | 4096 | 34 | 2 | 1 B |
| 12x2 | anonymous hidden | reply | 950 | 2877 | 2848 | 4096 | 31 | 2 | 1 B |
| 12x2 | anonymous hidden | messages | 25 | 2875 | 2845 | 4094 | 31 | 2 | 32 B |
| 12x2 | anonymous hidden | message bytes | 818 | 2877 | 2847 | 4096 | 31 | 2 | 1 B |
| 12x2 | anonymous public owners | reply | 821 | 2684 | 2622 | 4096 | 35 | 3 | 1 B |
| 12x2 | anonymous public owners | messages | 21 | 2675 | 2612 | 4087 | 35 | 3 | 25 B |
| 12x2 | anonymous public owners | message bytes | 689 | 2684 | 2621 | 4096 | 35 | 3 | 1 B |
| 12x2 | confidential entry | messages | none | - | - | - | - | - | 1409 B |
| 12x2 | confidential entry | message bytes | none | - | - | - | - | - | 1444 B |
| 12x2 | anonymous entry | reply | none | - | - | - | - | - | 1587 B |
| 12x2 | anonymous entry | messages | none | - | - | - | - | - | 1587 B |
| 12x2 | anonymous entry | message bytes | none | - | - | - | - | - | 1622 B |
| 12x4 | confidential signer | messages | 10 | 2658 | 2657 | 4070 | 35 | 3 | 8 B |
| 12x4 | confidential signer | message bytes | 332 | 2684 | 2683 | 4096 | 35 | 3 | 1 B |
| 12x4 | confidential in-proof | messages | 10 | 2754 | 2754 | 4069 | 34 | 2 | 7 B |
| 12x4 | confidential in-proof | message bytes | 333 | 2781 | 2781 | 4096 | 34 | 2 | 1 B |
| 12x4 | anonymous hidden | reply | none | - | - | - | - | - | 37 B |
| 12x4 | anonymous hidden | messages | none | - | - | - | - | - | 37 B |
| 12x4 | anonymous hidden | message bytes | none | - | - | - | - | - | 72 B |
| 12x4 | anonymous public owners | reply | none | - | - | - | - | - | 166 B |
| 12x4 | anonymous public owners | messages | none | - | - | - | - | - | 166 B |
| 12x4 | anonymous public owners | message bytes | none | - | - | - | - | - | 201 B |
| 12x8 | confidential signer | messages | none | - | - | - | - | - | 897 B |
| 12x8 | confidential signer | message bytes | none | - | - | - | - | - | 932 B |
| 12x8 | confidential in-proof | messages | none | - | - | - | - | - | 896 B |
| 12x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 931 B |
| 12x8 | anonymous hidden | reply | none | - | - | - | - | - | 1817 B |
| 12x8 | anonymous hidden | messages | none | - | - | - | - | - | 1817 B |
| 12x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1852 B |
| 12x8 | anonymous public owners | reply | none | - | - | - | - | - | 1946 B |
| 12x8 | anonymous public owners | messages | none | - | - | - | - | - | 1946 B |
| 12x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1981 B |
| 16x2 | confidential signer | messages | 21 | 2528 | 2463 | 4072 | 39 | 3 | 10 B |
| 16x2 | confidential signer | message bytes | 704 | 2552 | 2487 | 4096 | 39 | 3 | 1 B |
| 16x2 | confidential in-proof | messages | 21 | 2624 | 2560 | 4071 | 38 | 2 | 9 B |
| 16x2 | confidential in-proof | message bytes | 705 | 2649 | 2585 | 4096 | 38 | 2 | 1 B |
| 16x2 | anonymous hidden | reply | 690 | 2745 | 2720 | 4096 | 35 | 2 | 1 B |
| 16x2 | anonymous hidden | messages | 17 | 2731 | 2705 | 4082 | 35 | 2 | 20 B |
| 16x2 | anonymous hidden | message bytes | 558 | 2745 | 2719 | 4096 | 35 | 2 | 1 B |
| 16x2 | anonymous public owners | reply | 561 | 2552 | 2494 | 4096 | 39 | 3 | 1 B |
| 16x2 | anonymous public owners | messages | 13 | 2531 | 2472 | 4075 | 39 | 3 | 13 B |
| 16x2 | anonymous public owners | message bytes | 429 | 2552 | 2493 | 4096 | 39 | 3 | 1 B |
| 16x2 | confidential entry | messages | none | - | - | - | - | - | 2469 B |
| 16x2 | confidential entry | message bytes | none | - | - | - | - | - | 2504 B |
| 16x2 | anonymous entry | reply | none | - | - | - | - | - | 2647 B |
| 16x2 | anonymous entry | messages | none | - | - | - | - | - | 2647 B |
| 16x2 | anonymous entry | message bytes | none | - | - | - | - | - | 2682 B |
| 16x4 | confidential signer | messages | 3 | 2548 | 2551 | 4092 | 39 | 3 | 30 B |
| 16x4 | confidential signer | message bytes | 72 | 2552 | 2555 | 4096 | 39 | 3 | 1 B |
| 16x4 | confidential in-proof | messages | 3 | 2644 | 2648 | 4091 | 38 | 2 | 29 B |
| 16x4 | confidential in-proof | message bytes | 73 | 2649 | 2653 | 4096 | 38 | 2 | 1 B |
| 16x4 | anonymous hidden | reply | none | - | - | - | - | - | 297 B |
| 16x4 | anonymous hidden | messages | none | - | - | - | - | - | 297 B |
| 16x4 | anonymous hidden | message bytes | none | - | - | - | - | - | 332 B |
| 16x4 | anonymous public owners | reply | none | - | - | - | - | - | 426 B |
| 16x4 | anonymous public owners | messages | none | - | - | - | - | - | 426 B |
| 16x4 | anonymous public owners | message bytes | none | - | - | - | - | - | 461 B |
| 16x8 | confidential signer | messages | none | - | - | - | - | - | 1157 B |
| 16x8 | confidential signer | message bytes | none | - | - | - | - | - | 1192 B |
| 16x8 | confidential in-proof | messages | none | - | - | - | - | - | 1156 B |
| 16x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 1191 B |
| 16x8 | anonymous hidden | reply | none | - | - | - | - | - | 2077 B |
| 16x8 | anonymous hidden | messages | none | - | - | - | - | - | 2077 B |
| 16x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 2112 B |
| 16x8 | anonymous public owners | reply | none | - | - | - | - | - | 2206 B |
| 16x8 | anonymous public owners | messages | none | - | - | - | - | - | 2206 B |
| 16x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 2241 B |
| 24x2 | confidential signer | messages | 6 | 2275 | 2217 | 4083 | 47 | 3 | 21 B |
| 24x2 | confidential signer | message bytes | 183 | 2288 | 2230 | 4096 | 47 | 3 | 1 B |
| 24x2 | confidential in-proof | messages | 6 | 2371 | 2314 | 4082 | 46 | 2 | 20 B |
| 24x2 | confidential in-proof | message bytes | 184 | 2385 | 2328 | 4096 | 46 | 2 | 1 B |
| 24x2 | anonymous hidden | reply | 169 | 2481 | 2463 | 4096 | 43 | 2 | 1 B |
| 24x2 | anonymous hidden | messages | 2 | 2478 | 2459 | 4093 | 43 | 2 | 31 B |
| 24x2 | anonymous hidden | message bytes | 37 | 2481 | 2462 | 4096 | 43 | 2 | 1 B |
| 24x2 | anonymous public owners | reply | none | - | - | - | - | - | 57 B |
| 24x2 | anonymous public owners | messages | none | - | - | - | - | - | 57 B |
| 24x2 | anonymous public owners | message bytes | none | - | - | - | - | - | 92 B |
| 24x2 | confidential entry | messages | none | - | - | - | - | - | 4590 B |
| 24x2 | confidential entry | message bytes | none | - | - | - | - | - | 4625 B |
| 24x2 | anonymous entry | reply | none | - | - | - | - | - | 4768 B |
| 24x2 | anonymous entry | messages | none | - | - | - | - | - | 4768 B |
| 24x2 | anonymous entry | message bytes | none | - | - | - | - | - | 4803 B |
| 24x4 | confidential signer | messages | none | - | - | - | - | - | 414 B |
| 24x4 | confidential signer | message bytes | none | - | - | - | - | - | 449 B |
| 24x4 | confidential in-proof | messages | none | - | - | - | - | - | 413 B |
| 24x4 | confidential in-proof | message bytes | none | - | - | - | - | - | 448 B |
| 24x4 | anonymous hidden | reply | none | - | - | - | - | - | 818 B |
| 24x4 | anonymous hidden | messages | none | - | - | - | - | - | 818 B |
| 24x4 | anonymous hidden | message bytes | none | - | - | - | - | - | 853 B |
| 24x4 | anonymous public owners | reply | none | - | - | - | - | - | 947 B |
| 24x4 | anonymous public owners | messages | none | - | - | - | - | - | 947 B |
| 24x4 | anonymous public owners | message bytes | none | - | - | - | - | - | 982 B |
| 32x2 | confidential signer | messages | none | - | - | - | - | - | 303 B |
| 32x2 | confidential signer | message bytes | none | - | - | - | - | - | 338 B |
| 32x2 | confidential in-proof | messages | none | - | - | - | - | - | 302 B |
| 32x2 | confidential in-proof | message bytes | none | - | - | - | - | - | 337 B |
| 32x2 | anonymous hidden | reply | none | - | - | - | - | - | 449 B |
| 32x2 | anonymous hidden | messages | none | - | - | - | - | - | 449 B |
| 32x2 | anonymous hidden | message bytes | none | - | - | - | - | - | 484 B |
| 32x2 | anonymous public owners | reply | none | - | - | - | - | - | 578 B |
| 32x2 | anonymous public owners | messages | none | - | - | - | - | - | 578 B |
| 32x2 | anonymous public owners | message bytes | none | - | - | - | - | - | 613 B |
| 40x2 | confidential signer | messages | none | - | - | - | - | - | 824 B |
| 40x2 | confidential signer | message bytes | none | - | - | - | - | - | 859 B |
| 40x2 | confidential in-proof | messages | none | - | - | - | - | - | 823 B |
| 40x2 | confidential in-proof | message bytes | none | - | - | - | - | - | 858 B |
| 40x2 | anonymous hidden | reply | none | - | - | - | - | - | 970 B |
| 40x2 | anonymous hidden | messages | none | - | - | - | - | - | 970 B |
| 40x2 | anonymous hidden | message bytes | none | - | - | - | - | - | 1005 B |
| 40x2 | anonymous public owners | reply | none | - | - | - | - | - | 1099 B |
| 40x2 | anonymous public owners | messages | none | - | - | - | - | - | 1099 B |
| 40x2 | anonymous public owners | message bytes | none | - | - | - | - | - | 1134 B |
| 48x2 | confidential signer | messages | none | - | - | - | - | - | 1345 B, 7 accounts |
| 48x2 | confidential signer | message bytes | none | - | - | - | - | - | 1380 B, 7 accounts |
| 48x2 | confidential in-proof | messages | none | - | - | - | - | - | 1344 B, 6 accounts |
| 48x2 | confidential in-proof | message bytes | none | - | - | - | - | - | 1379 B, 6 accounts |
| 48x2 | anonymous hidden | reply | none | - | - | - | - | - | 1491 B, 3 accounts |
| 48x2 | anonymous hidden | messages | none | - | - | - | - | - | 1491 B, 3 accounts |
| 48x2 | anonymous hidden | message bytes | none | - | - | - | - | - | 1526 B, 3 accounts |
| 48x2 | anonymous public owners | reply | none | - | - | - | - | - | 1620 B, 7 accounts |
| 48x2 | anonymous public owners | messages | none | - | - | - | - | - | 1620 B, 7 accounts |
| 48x2 | anonymous public owners | message bytes | none | - | - | - | - | - | 1655 B, 7 accounts |
| 49x2 | confidential signer | messages | none | - | - | - | - | - | 1411 B, 8 accounts |
| 49x2 | confidential signer | message bytes | none | - | - | - | - | - | 1446 B, 8 accounts |
| 49x2 | confidential in-proof | messages | none | - | - | - | - | - | 1410 B, 7 accounts |
| 49x2 | confidential in-proof | message bytes | none | - | - | - | - | - | 1445 B, 7 accounts |
| 49x2 | anonymous hidden | reply | none | - | - | - | - | - | 1557 B, 4 accounts |
| 49x2 | anonymous hidden | messages | none | - | - | - | - | - | 1557 B, 4 accounts |
| 49x2 | anonymous hidden | message bytes | none | - | - | - | - | - | 1592 B, 4 accounts |
| 49x2 | anonymous public owners | reply | none | - | - | - | - | - | 1686 B, 8 accounts |
| 49x2 | anonymous public owners | messages | none | - | - | - | - | - | 1686 B, 8 accounts |
| 49x2 | anonymous public owners | message bytes | none | - | - | - | - | - | 1721 B, 8 accounts |
