Measured with the frame encoders, SPP's account builders and the v1 compiler. Ceilings 4096 B, 64 accounts, 12 signatures.
min: tracking root, no co-signer, no leg, no fee, the payer an owner where it may be. full: own, curator and tracking roots, one co-signer, 4 SOL legs, a fee, an outside payer, a body on every slot and one exit. The owner run is the ceilings' bound under full, the key's rows bound it apart. A shape's every input and output slot is published.
Every row is one transaction. fits: the row clears the transaction and CPI ceilings. limit: what refuses a row, rail for a shape the rail has no SPP key for, else the excess in accounts, signatures, bytes or CPI data at that row's load. A missing catalog key has no encoded measurement.
| shape | rail | load | catalog key | bytes | accounts | signatures | owner run | frame | SPP CPI | fits | limit |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1x2 | confidential signer | min | yes | 1348 | 9 | 1 | - | 932 | 945 | yes |  |
| 1x2 | confidential signer | full | yes | 1903 | 19 | 3 | 1 | 1019 | 990 | yes |  |
| 1x2 | confidential signer | full+spl | yes | 2271 | 26 | 3 | - | 1151 | 994 | yes |  |
| 1x2 | confidential signer | full+data | yes | 2103 | 19 | 3 | - | 1219 | 1186 | yes |  |
| 1x2 | confidential signer | full+reply | yes | 1903 | 19 | 3 | - | 1019 | 990 | yes |  |
| 1x2 | confidential signer | full+2tree | yes | 1941 | 20 | 3 | - | 1024 | 994 | yes |  |
| 1x2 | confidential in-proof | min | yes | 1443 | 9 | 1 | - | 1028 | 1042 | yes |  |
| 1x2 | confidential in-proof | full | yes | 1902 | 18 | 2 | 1 | 1115 | 1087 | yes |  |
| 1x2 | confidential in-proof | full+spl | yes | 2270 | 25 | 2 | - | 1247 | 1091 | yes |  |
| 1x2 | confidential in-proof | full+data | yes | 2102 | 18 | 2 | - | 1315 | 1283 | yes |  |
| 1x2 | confidential in-proof | full+reply | yes | 1902 | 18 | 2 | - | 1115 | 1087 | yes |  |
| 1x2 | confidential in-proof | full+2tree | yes | 1940 | 19 | 2 | - | 1120 | 1091 | yes |  |
| 1x2 | anonymous hidden | min | yes | 1475 | 9 | 1 | - | 1060 | 1104 | yes |  |
| 1x2 | anonymous hidden | full | yes | 1902 | 15 | 2 | 1 | 1211 | 1223 | yes |  |
| 1x2 | anonymous hidden | full+spl | yes | 2270 | 22 | 2 | - | 1343 | 1227 | yes |  |
| 1x2 | anonymous hidden | full+data | yes | 2102 | 15 | 2 | - | 1411 | 1419 | yes |  |
| 1x2 | anonymous hidden | full+reply | yes | 2001 | 15 | 2 | - | 1310 | 1320 | yes |  |
| 1x2 | anonymous hidden | full+2tree | yes | 1940 | 16 | 2 | - | 1216 | 1227 | yes |  |
| 1x2 | anonymous public owners | min | yes | 1412 | 9 | 1 | - | 996 | 1007 | yes |  |
| 1x2 | anonymous public owners | full | yes | 2031 | 19 | 3 | 1 | 1147 | 1126 | yes |  |
| 1x2 | anonymous public owners | full+spl | yes | 2399 | 26 | 3 | - | 1279 | 1130 | yes |  |
| 1x2 | anonymous public owners | full+data | yes | 2231 | 19 | 3 | - | 1347 | 1322 | yes |  |
| 1x2 | anonymous public owners | full+reply | yes | 2130 | 19 | 3 | - | 1246 | 1223 | yes |  |
| 1x2 | anonymous public owners | full+2tree | yes | 2069 | 20 | 3 | - | 1152 | 1130 | yes |  |
| 1x2 | confidential entry | min | yes | 1556 | 9 | 1 | - | 1140 | 1153 | yes |  |
| 1x2 | confidential entry | full | yes | 2111 | 19 | 3 | 1 | 1227 | 1198 | yes |  |
| 1x2 | confidential entry | full+spl | yes | 2479 | 26 | 3 | - | 1359 | 1202 | yes |  |
| 1x2 | confidential entry | full+data | yes | 2311 | 19 | 3 | - | 1427 | 1394 | yes |  |
| 1x2 | confidential entry | full+reply | yes | 2111 | 19 | 3 | - | 1227 | 1198 | yes |  |
| 1x2 | confidential entry | full+2tree | yes | 2149 | 20 | 3 | - | 1232 | 1202 | yes |  |
| 1x2 | anonymous entry | min | yes | 1715 | 9 | 1 | - | 1300 | 1312 | yes |  |
| 1x2 | anonymous entry | full | yes | 2142 | 15 | 2 | 1 | 1451 | 1431 | yes |  |
| 1x2 | anonymous entry | full+spl | yes | 2510 | 22 | 2 | - | 1583 | 1435 | yes |  |
| 1x2 | anonymous entry | full+data | yes | 2342 | 15 | 2 | - | 1651 | 1627 | yes |  |
| 1x2 | anonymous entry | full+reply | yes | 2241 | 15 | 2 | - | 1550 | 1528 | yes |  |
| 1x2 | anonymous entry | full+2tree | yes | 2180 | 16 | 2 | - | 1456 | 1435 | yes |  |
| 1x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x4 | confidential signer | min | yes | 1782 | 9 | 1 | - | 1366 | 1451 | yes |  |
| 1x4 | confidential signer | full | yes | 2337 | 19 | 3 | 1 | 1453 | 1496 | yes |  |
| 1x4 | confidential signer | full+spl | yes | 2705 | 26 | 3 | - | 1585 | 1500 | yes |  |
| 1x4 | confidential signer | full+data | yes | 2735 | 19 | 3 | - | 1851 | 1886 | yes |  |
| 1x4 | confidential signer | full+reply | yes | 2337 | 19 | 3 | - | 1453 | 1496 | yes |  |
| 1x4 | confidential signer | full+2tree | yes | 2375 | 20 | 3 | - | 1458 | 1500 | yes |  |
| 1x4 | confidential in-proof | min | yes | 1877 | 9 | 1 | - | 1462 | 1548 | yes |  |
| 1x4 | confidential in-proof | full | yes | 2336 | 18 | 2 | 1 | 1549 | 1593 | yes |  |
| 1x4 | confidential in-proof | full+spl | yes | 2704 | 25 | 2 | - | 1681 | 1597 | yes |  |
| 1x4 | confidential in-proof | full+data | yes | 2734 | 18 | 2 | - | 1947 | 1983 | yes |  |
| 1x4 | confidential in-proof | full+reply | yes | 2336 | 18 | 2 | - | 1549 | 1593 | yes |  |
| 1x4 | confidential in-proof | full+2tree | yes | 2374 | 19 | 2 | - | 1554 | 1597 | yes |  |
| 1x4 | anonymous hidden | min | yes | 1973 | 9 | 1 | - | 1558 | 1674 | yes |  |
| 1x4 | anonymous hidden | full | yes | 2400 | 15 | 2 | 1 | 1709 | 1793 | yes |  |
| 1x4 | anonymous hidden | full+spl | yes | 2768 | 22 | 2 | - | 1841 | 1797 | yes |  |
| 1x4 | anonymous hidden | full+data | yes | 2798 | 15 | 2 | - | 2107 | 2183 | yes |  |
| 1x4 | anonymous hidden | full+reply | yes | 2693 | 15 | 2 | - | 2002 | 2084 | yes |  |
| 1x4 | anonymous hidden | full+2tree | yes | 2438 | 16 | 2 | - | 1714 | 1797 | yes |  |
| 1x4 | anonymous public owners | min | yes | 1910 | 9 | 1 | - | 1494 | 1577 | yes |  |
| 1x4 | anonymous public owners | full | yes | 2529 | 19 | 3 | 1 | 1645 | 1696 | yes |  |
| 1x4 | anonymous public owners | full+spl | yes | 2897 | 26 | 3 | - | 1777 | 1700 | yes |  |
| 1x4 | anonymous public owners | full+data | yes | 2927 | 19 | 3 | - | 2043 | 2086 | yes |  |
| 1x4 | anonymous public owners | full+reply | yes | 2822 | 19 | 3 | - | 1938 | 1987 | yes |  |
| 1x4 | anonymous public owners | full+2tree | yes | 2567 | 20 | 3 | - | 1650 | 1700 | yes |  |
| 1x4 | confidential entry | min | yes | 1990 | 9 | 1 | - | 1574 | 1659 | yes |  |
| 1x4 | confidential entry | full | yes | 2545 | 19 | 3 | 1 | 1661 | 1704 | yes |  |
| 1x4 | confidential entry | full+spl | yes | 2913 | 26 | 3 | - | 1793 | 1708 | yes |  |
| 1x4 | confidential entry | full+data | yes | 2943 | 19 | 3 | - | 2059 | 2094 | yes |  |
| 1x4 | confidential entry | full+reply | yes | 2545 | 19 | 3 | - | 1661 | 1704 | yes |  |
| 1x4 | confidential entry | full+2tree | yes | 2583 | 20 | 3 | - | 1666 | 1708 | yes |  |
| 1x4 | anonymous entry | min | yes | 2213 | 9 | 1 | - | 1798 | 1882 | yes |  |
| 1x4 | anonymous entry | full | yes | 2640 | 15 | 2 | 1 | 1949 | 2001 | yes |  |
| 1x4 | anonymous entry | full+spl | yes | 3008 | 22 | 2 | - | 2081 | 2005 | yes |  |
| 1x4 | anonymous entry | full+data | yes | 3038 | 15 | 2 | - | 2347 | 2391 | yes |  |
| 1x4 | anonymous entry | full+reply | yes | 2933 | 15 | 2 | - | 2242 | 2292 | yes |  |
| 1x4 | anonymous entry | full+2tree | yes | 2678 | 16 | 2 | - | 1954 | 2005 | yes |  |
| 1x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x8 | confidential signer | min | yes | 2650 | 9 | 1 | - | 2234 | 2463 | yes |  |
| 1x8 | confidential signer | full | yes | 3205 | 19 | 3 | 1 | 2321 | 2508 | yes |  |
| 1x8 | confidential signer | full+spl | yes | 3573 | 26 | 3 | - | 2453 | 2512 | yes |  |
| 1x8 | confidential signer | full+data | yes | 3999 | 19 | 3 | - | 3115 | 3286 | yes |  |
| 1x8 | confidential signer | full+reply | yes | 3205 | 19 | 3 | - | 2321 | 2508 | yes |  |
| 1x8 | confidential signer | full+2tree | yes | 3243 | 20 | 3 | - | 2326 | 2512 | yes |  |
| 1x8 | confidential in-proof | min | yes | 2745 | 9 | 1 | - | 2330 | 2560 | yes |  |
| 1x8 | confidential in-proof | full | yes | 3204 | 18 | 2 | 1 | 2417 | 2605 | yes |  |
| 1x8 | confidential in-proof | full+spl | yes | 3572 | 25 | 2 | - | 2549 | 2609 | yes |  |
| 1x8 | confidential in-proof | full+data | yes | 3998 | 18 | 2 | - | 3211 | 3383 | yes |  |
| 1x8 | confidential in-proof | full+reply | yes | 3204 | 18 | 2 | - | 2417 | 2605 | yes |  |
| 1x8 | confidential in-proof | full+2tree | yes | 3242 | 19 | 2 | - | 2422 | 2609 | yes |  |
| 1x8 | anonymous hidden | min | yes | 2969 | 9 | 1 | - | 2554 | 2814 | yes |  |
| 1x8 | anonymous hidden | full | yes | 3396 | 15 | 2 | 1 | 2705 | 2933 | yes |  |
| 1x8 | anonymous hidden | full+spl | yes | 3764 | 22 | 2 | - | 2837 | 2937 | yes |  |
| 1x8 | anonymous hidden | full+data | yes | 4190 | 15 | 2 | - | 3499 | 3711 | no | 94 B |
| 1x8 | anonymous hidden | full+reply | yes | 4077 | 15 | 2 | - | 3386 | 3612 | yes |  |
| 1x8 | anonymous hidden | full+2tree | yes | 3434 | 16 | 2 | - | 2710 | 2937 | yes |  |
| 1x8 | anonymous public owners | min | yes | 2906 | 9 | 1 | - | 2490 | 2717 | yes |  |
| 1x8 | anonymous public owners | full | yes | 3525 | 19 | 3 | 1 | 2641 | 2836 | yes |  |
| 1x8 | anonymous public owners | full+spl | yes | 3893 | 26 | 3 | - | 2773 | 2840 | yes |  |
| 1x8 | anonymous public owners | full+data | yes | 4319 | 19 | 3 | - | 3435 | 3614 | no | 223 B |
| 1x8 | anonymous public owners | full+reply | yes | 4206 | 19 | 3 | - | 3322 | 3515 | no | 110 B |
| 1x8 | anonymous public owners | full+2tree | yes | 3563 | 20 | 3 | - | 2646 | 2840 | yes |  |
| 1x8 | confidential entry | min | yes | 2858 | 9 | 1 | - | 2442 | 2671 | yes |  |
| 1x8 | confidential entry | full | yes | 3413 | 19 | 3 | 1 | 2529 | 2716 | yes |  |
| 1x8 | confidential entry | full+spl | yes | 3781 | 26 | 3 | - | 2661 | 2720 | yes |  |
| 1x8 | confidential entry | full+data | yes | 4207 | 19 | 3 | - | 3323 | 3494 | no | 111 B |
| 1x8 | confidential entry | full+reply | yes | 3413 | 19 | 3 | - | 2529 | 2716 | yes |  |
| 1x8 | confidential entry | full+2tree | yes | 3451 | 20 | 3 | - | 2534 | 2720 | yes |  |
| 1x8 | anonymous entry | min | yes | 3209 | 9 | 1 | - | 2794 | 3022 | yes |  |
| 1x8 | anonymous entry | full | yes | 3636 | 15 | 2 | 1 | 2945 | 3141 | yes |  |
| 1x8 | anonymous entry | full+spl | yes | 4004 | 22 | 2 | - | 3077 | 3145 | yes |  |
| 1x8 | anonymous entry | full+data | yes | 4430 | 15 | 2 | - | 3739 | 3919 | no | 334 B |
| 1x8 | anonymous entry | full+reply | yes | 4317 | 15 | 2 | - | 3626 | 3820 | no | 221 B |
| 1x8 | anonymous entry | full+2tree | yes | 3674 | 16 | 2 | - | 2950 | 3145 | yes |  |
| 1x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x2 | confidential signer | min | yes | 1413 | 10 | 1 | - | 964 | 978 | yes |  |
| 2x2 | confidential signer | full | yes | 1968 | 20 | 3 | 2 | 1051 | 1023 | yes |  |
| 2x2 | confidential signer | full+spl | yes | 2336 | 27 | 3 | - | 1183 | 1027 | yes |  |
| 2x2 | confidential signer | full+data | yes | 2168 | 20 | 3 | - | 1251 | 1219 | yes |  |
| 2x2 | confidential signer | full+reply | yes | 1968 | 20 | 3 | - | 1051 | 1023 | yes |  |
| 2x2 | confidential signer | full+2tree | yes | 2006 | 21 | 3 | - | 1056 | 1027 | yes |  |
| 2x2 | confidential in-proof | min | yes | 1508 | 10 | 1 | - | 1060 | 1075 | yes |  |
| 2x2 | confidential in-proof | full | yes | 1967 | 19 | 2 | 2 | 1147 | 1120 | yes |  |
| 2x2 | confidential in-proof | full+spl | yes | 2335 | 26 | 2 | - | 1279 | 1124 | yes |  |
| 2x2 | confidential in-proof | full+data | yes | 2167 | 19 | 2 | - | 1347 | 1316 | yes |  |
| 2x2 | confidential in-proof | full+reply | yes | 1967 | 19 | 2 | - | 1147 | 1120 | yes |  |
| 2x2 | confidential in-proof | full+2tree | yes | 2005 | 20 | 2 | - | 1152 | 1124 | yes |  |
| 2x2 | anonymous hidden | min | yes | 1540 | 10 | 1 | - | 1092 | 1137 | yes |  |
| 2x2 | anonymous hidden | full | yes | 1967 | 16 | 2 | 2 | 1243 | 1256 | yes |  |
| 2x2 | anonymous hidden | full+spl | yes | 2335 | 23 | 2 | - | 1375 | 1260 | yes |  |
| 2x2 | anonymous hidden | full+data | yes | 2167 | 16 | 2 | - | 1443 | 1452 | yes |  |
| 2x2 | anonymous hidden | full+reply | yes | 2066 | 16 | 2 | - | 1342 | 1353 | yes |  |
| 2x2 | anonymous hidden | full+2tree | yes | 2005 | 17 | 2 | - | 1248 | 1260 | yes |  |
| 2x2 | anonymous public owners | min | yes | 1477 | 10 | 1 | - | 1028 | 1040 | yes |  |
| 2x2 | anonymous public owners | full | yes | 2096 | 20 | 3 | 2 | 1179 | 1159 | yes |  |
| 2x2 | anonymous public owners | full+spl | yes | 2464 | 27 | 3 | - | 1311 | 1163 | yes |  |
| 2x2 | anonymous public owners | full+data | yes | 2296 | 20 | 3 | - | 1379 | 1355 | yes |  |
| 2x2 | anonymous public owners | full+reply | yes | 2195 | 20 | 3 | - | 1278 | 1256 | yes |  |
| 2x2 | anonymous public owners | full+2tree | yes | 2134 | 21 | 3 | - | 1184 | 1163 | yes |  |
| 2x2 | confidential entry | min | yes | 1821 | 10 | 1 | - | 1372 | 1386 | yes |  |
| 2x2 | confidential entry | full | yes | 2376 | 20 | 3 | 2 | 1459 | 1431 | yes |  |
| 2x2 | confidential entry | full+spl | yes | 2744 | 27 | 3 | - | 1591 | 1435 | yes |  |
| 2x2 | confidential entry | full+data | yes | 2576 | 20 | 3 | - | 1659 | 1627 | yes |  |
| 2x2 | confidential entry | full+reply | yes | 2376 | 20 | 3 | - | 1459 | 1431 | yes |  |
| 2x2 | confidential entry | full+2tree | yes | 2414 | 21 | 3 | - | 1464 | 1435 | yes |  |
| 2x2 | anonymous entry | min | yes | 1980 | 10 | 1 | - | 1532 | 1545 | yes |  |
| 2x2 | anonymous entry | full | yes | 2407 | 16 | 2 | 2 | 1683 | 1664 | yes |  |
| 2x2 | anonymous entry | full+spl | yes | 2775 | 23 | 2 | - | 1815 | 1668 | yes |  |
| 2x2 | anonymous entry | full+data | yes | 2607 | 16 | 2 | - | 1883 | 1860 | yes |  |
| 2x2 | anonymous entry | full+reply | yes | 2506 | 16 | 2 | - | 1782 | 1761 | yes |  |
| 2x2 | anonymous entry | full+2tree | yes | 2445 | 17 | 2 | - | 1688 | 1668 | yes |  |
| 2x2 | delegate | min | yes | 1413 | 10 | 1 | - | 964 | 978 | yes |  |
| 2x2 | delegate | full | yes | 1756 | 16 | 2 | - | 1035 | 1023 | yes |  |
| 2x2 | delegate | full+spl | yes | 1996 | 23 | 2 | - | 1039 | 1027 | yes |  |
| 2x2 | delegate | full+data | yes | 1956 | 16 | 2 | - | 1235 | 1219 | yes |  |
| 2x2 | delegate | full+reply | yes | 1756 | 16 | 2 | - | 1035 | 1023 | yes |  |
| 2x2 | delegate | full+2tree | yes | 1794 | 17 | 2 | - | 1040 | 1027 | yes |  |
| 2x2 | anonymous delegate | min | yes | 1477 | 10 | 1 | - | 1028 | 1040 | yes |  |
| 2x2 | anonymous delegate | full | yes | 1884 | 16 | 2 | - | 1163 | 1159 | yes |  |
| 2x2 | anonymous delegate | full+spl | yes | 2124 | 23 | 2 | - | 1167 | 1163 | yes |  |
| 2x2 | anonymous delegate | full+data | yes | 2084 | 16 | 2 | - | 1363 | 1355 | yes |  |
| 2x2 | anonymous delegate | full+reply | yes | 1983 | 16 | 2 | - | 1262 | 1256 | yes |  |
| 2x2 | anonymous delegate | full+2tree | yes | 1922 | 17 | 2 | - | 1168 | 1163 | yes |  |
| 2x4 | confidential signer | min | yes | 1847 | 10 | 1 | - | 1398 | 1484 | yes |  |
| 2x4 | confidential signer | full | yes | 2402 | 20 | 3 | 2 | 1485 | 1529 | yes |  |
| 2x4 | confidential signer | full+spl | yes | 2770 | 27 | 3 | - | 1617 | 1533 | yes |  |
| 2x4 | confidential signer | full+data | yes | 2800 | 20 | 3 | - | 1883 | 1919 | yes |  |
| 2x4 | confidential signer | full+reply | yes | 2402 | 20 | 3 | - | 1485 | 1529 | yes |  |
| 2x4 | confidential signer | full+2tree | yes | 2440 | 21 | 3 | - | 1490 | 1533 | yes |  |
| 2x4 | confidential in-proof | min | yes | 1942 | 10 | 1 | - | 1494 | 1581 | yes |  |
| 2x4 | confidential in-proof | full | yes | 2401 | 19 | 2 | 2 | 1581 | 1626 | yes |  |
| 2x4 | confidential in-proof | full+spl | yes | 2769 | 26 | 2 | - | 1713 | 1630 | yes |  |
| 2x4 | confidential in-proof | full+data | yes | 2799 | 19 | 2 | - | 1979 | 2016 | yes |  |
| 2x4 | confidential in-proof | full+reply | yes | 2401 | 19 | 2 | - | 1581 | 1626 | yes |  |
| 2x4 | confidential in-proof | full+2tree | yes | 2439 | 20 | 2 | - | 1586 | 1630 | yes |  |
| 2x4 | anonymous hidden | min | yes | 2038 | 10 | 1 | - | 1590 | 1707 | yes |  |
| 2x4 | anonymous hidden | full | yes | 2465 | 16 | 2 | 2 | 1741 | 1826 | yes |  |
| 2x4 | anonymous hidden | full+spl | yes | 2833 | 23 | 2 | - | 1873 | 1830 | yes |  |
| 2x4 | anonymous hidden | full+data | yes | 2863 | 16 | 2 | - | 2139 | 2216 | yes |  |
| 2x4 | anonymous hidden | full+reply | yes | 2758 | 16 | 2 | - | 2034 | 2117 | yes |  |
| 2x4 | anonymous hidden | full+2tree | yes | 2503 | 17 | 2 | - | 1746 | 1830 | yes |  |
| 2x4 | anonymous public owners | min | yes | 1975 | 10 | 1 | - | 1526 | 1610 | yes |  |
| 2x4 | anonymous public owners | full | yes | 2594 | 20 | 3 | 2 | 1677 | 1729 | yes |  |
| 2x4 | anonymous public owners | full+spl | yes | 2962 | 27 | 3 | - | 1809 | 1733 | yes |  |
| 2x4 | anonymous public owners | full+data | yes | 2992 | 20 | 3 | - | 2075 | 2119 | yes |  |
| 2x4 | anonymous public owners | full+reply | yes | 2887 | 20 | 3 | - | 1970 | 2020 | yes |  |
| 2x4 | anonymous public owners | full+2tree | yes | 2632 | 21 | 3 | - | 1682 | 1733 | yes |  |
| 2x4 | confidential entry | min | yes | 2255 | 10 | 1 | - | 1806 | 1892 | yes |  |
| 2x4 | confidential entry | full | yes | 2810 | 20 | 3 | 2 | 1893 | 1937 | yes |  |
| 2x4 | confidential entry | full+spl | yes | 3178 | 27 | 3 | - | 2025 | 1941 | yes |  |
| 2x4 | confidential entry | full+data | yes | 3208 | 20 | 3 | - | 2291 | 2327 | yes |  |
| 2x4 | confidential entry | full+reply | yes | 2810 | 20 | 3 | - | 1893 | 1937 | yes |  |
| 2x4 | confidential entry | full+2tree | yes | 2848 | 21 | 3 | - | 1898 | 1941 | yes |  |
| 2x4 | anonymous entry | min | yes | 2478 | 10 | 1 | - | 2030 | 2115 | yes |  |
| 2x4 | anonymous entry | full | yes | 2905 | 16 | 2 | 2 | 2181 | 2234 | yes |  |
| 2x4 | anonymous entry | full+spl | yes | 3273 | 23 | 2 | - | 2313 | 2238 | yes |  |
| 2x4 | anonymous entry | full+data | yes | 3303 | 16 | 2 | - | 2579 | 2624 | yes |  |
| 2x4 | anonymous entry | full+reply | yes | 3198 | 16 | 2 | - | 2474 | 2525 | yes |  |
| 2x4 | anonymous entry | full+2tree | yes | 2943 | 17 | 2 | - | 2186 | 2238 | yes |  |
| 2x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x16 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x8 | confidential signer | min | yes | 2715 | 10 | 1 | - | 2266 | 2496 | yes |  |
| 2x8 | confidential signer | full | yes | 3270 | 20 | 3 | 2 | 2353 | 2541 | yes |  |
| 2x8 | confidential signer | full+spl | yes | 3638 | 27 | 3 | - | 2485 | 2545 | yes |  |
| 2x8 | confidential signer | full+data | yes | 4064 | 20 | 3 | - | 3147 | 3319 | yes |  |
| 2x8 | confidential signer | full+reply | yes | 3270 | 20 | 3 | - | 2353 | 2541 | yes |  |
| 2x8 | confidential signer | full+2tree | yes | 3308 | 21 | 3 | - | 2358 | 2545 | yes |  |
| 2x8 | confidential in-proof | min | yes | 2810 | 10 | 1 | - | 2362 | 2593 | yes |  |
| 2x8 | confidential in-proof | full | yes | 3269 | 19 | 2 | 2 | 2449 | 2638 | yes |  |
| 2x8 | confidential in-proof | full+spl | yes | 3637 | 26 | 2 | - | 2581 | 2642 | yes |  |
| 2x8 | confidential in-proof | full+data | yes | 4063 | 19 | 2 | - | 3243 | 3416 | yes |  |
| 2x8 | confidential in-proof | full+reply | yes | 3269 | 19 | 2 | - | 2449 | 2638 | yes |  |
| 2x8 | confidential in-proof | full+2tree | yes | 3307 | 20 | 2 | - | 2454 | 2642 | yes |  |
| 2x8 | anonymous hidden | min | yes | 3034 | 10 | 1 | - | 2586 | 2847 | yes |  |
| 2x8 | anonymous hidden | full | yes | 3461 | 16 | 2 | 2 | 2737 | 2966 | yes |  |
| 2x8 | anonymous hidden | full+spl | yes | 3829 | 23 | 2 | - | 2869 | 2970 | yes |  |
| 2x8 | anonymous hidden | full+data | yes | 4255 | 16 | 2 | - | 3531 | 3744 | no | 159 B |
| 2x8 | anonymous hidden | full+reply | yes | 4142 | 16 | 2 | - | 3418 | 3645 | no | 46 B |
| 2x8 | anonymous hidden | full+2tree | yes | 3499 | 17 | 2 | - | 2742 | 2970 | yes |  |
| 2x8 | anonymous public owners | min | yes | 2971 | 10 | 1 | - | 2522 | 2750 | yes |  |
| 2x8 | anonymous public owners | full | yes | 3590 | 20 | 3 | 2 | 2673 | 2869 | yes |  |
| 2x8 | anonymous public owners | full+spl | yes | 3958 | 27 | 3 | - | 2805 | 2873 | yes |  |
| 2x8 | anonymous public owners | full+data | yes | 4384 | 20 | 3 | - | 3467 | 3647 | no | 288 B |
| 2x8 | anonymous public owners | full+reply | yes | 4271 | 20 | 3 | - | 3354 | 3548 | no | 175 B |
| 2x8 | anonymous public owners | full+2tree | yes | 3628 | 21 | 3 | - | 2678 | 2873 | yes |  |
| 2x8 | confidential entry | min | yes | 3123 | 10 | 1 | - | 2674 | 2904 | yes |  |
| 2x8 | confidential entry | full | yes | 3678 | 20 | 3 | 2 | 2761 | 2949 | yes |  |
| 2x8 | confidential entry | full+spl | yes | 4046 | 27 | 3 | - | 2893 | 2953 | yes |  |
| 2x8 | confidential entry | full+data | yes | 4472 | 20 | 3 | - | 3555 | 3727 | no | 376 B |
| 2x8 | confidential entry | full+reply | yes | 3678 | 20 | 3 | - | 2761 | 2949 | yes |  |
| 2x8 | confidential entry | full+2tree | yes | 3716 | 21 | 3 | - | 2766 | 2953 | yes |  |
| 2x8 | anonymous entry | min | yes | 3474 | 10 | 1 | - | 3026 | 3255 | yes |  |
| 2x8 | anonymous entry | full | yes | 3901 | 16 | 2 | 2 | 3177 | 3374 | yes |  |
| 2x8 | anonymous entry | full+spl | yes | 4269 | 23 | 2 | - | 3309 | 3378 | no | 173 B |
| 2x8 | anonymous entry | full+data | yes | 4695 | 16 | 2 | - | 3971 | 4152 | no | 599 B |
| 2x8 | anonymous entry | full+reply | yes | 4582 | 16 | 2 | - | 3858 | 4053 | no | 486 B |
| 2x8 | anonymous entry | full+2tree | yes | 3939 | 17 | 2 | - | 3182 | 3378 | yes |  |
| 2x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x2 | confidential signer | min | yes | 1478 | 11 | 1 | - | 996 | 1011 | yes |  |
| 3x2 | confidential signer | full | yes | 2033 | 21 | 3 | 3 | 1083 | 1056 | yes |  |
| 3x2 | confidential signer | full+spl | yes | 2401 | 28 | 3 | - | 1215 | 1060 | yes |  |
| 3x2 | confidential signer | full+data | yes | 2233 | 21 | 3 | - | 1283 | 1252 | yes |  |
| 3x2 | confidential signer | full+reply | yes | 2033 | 21 | 3 | - | 1083 | 1056 | yes |  |
| 3x2 | confidential signer | full+2tree | yes | 2071 | 22 | 3 | - | 1088 | 1060 | yes |  |
| 3x2 | confidential in-proof | min | yes | 1573 | 11 | 1 | - | 1092 | 1108 | yes |  |
| 3x2 | confidential in-proof | full | yes | 2032 | 20 | 2 | 3 | 1179 | 1153 | yes |  |
| 3x2 | confidential in-proof | full+spl | yes | 2400 | 27 | 2 | - | 1311 | 1157 | yes |  |
| 3x2 | confidential in-proof | full+data | yes | 2232 | 20 | 2 | - | 1379 | 1349 | yes |  |
| 3x2 | confidential in-proof | full+reply | yes | 2032 | 20 | 2 | - | 1179 | 1153 | yes |  |
| 3x2 | confidential in-proof | full+2tree | yes | 2070 | 21 | 2 | - | 1184 | 1157 | yes |  |
| 3x2 | anonymous hidden | min | yes | 1605 | 11 | 1 | - | 1124 | 1170 | yes |  |
| 3x2 | anonymous hidden | full | yes | 2032 | 17 | 2 | 3 | 1275 | 1289 | yes |  |
| 3x2 | anonymous hidden | full+spl | yes | 2400 | 24 | 2 | - | 1407 | 1293 | yes |  |
| 3x2 | anonymous hidden | full+data | yes | 2232 | 17 | 2 | - | 1475 | 1485 | yes |  |
| 3x2 | anonymous hidden | full+reply | yes | 2131 | 17 | 2 | - | 1374 | 1386 | yes |  |
| 3x2 | anonymous hidden | full+2tree | yes | 2070 | 18 | 2 | - | 1280 | 1293 | yes |  |
| 3x2 | anonymous public owners | min | yes | 1542 | 11 | 1 | - | 1060 | 1073 | yes |  |
| 3x2 | anonymous public owners | full | yes | 2161 | 21 | 3 | 3 | 1211 | 1192 | yes |  |
| 3x2 | anonymous public owners | full+spl | yes | 2529 | 28 | 3 | - | 1343 | 1196 | yes |  |
| 3x2 | anonymous public owners | full+data | yes | 2361 | 21 | 3 | - | 1411 | 1388 | yes |  |
| 3x2 | anonymous public owners | full+reply | yes | 2260 | 21 | 3 | - | 1310 | 1289 | yes |  |
| 3x2 | anonymous public owners | full+2tree | yes | 2199 | 22 | 3 | - | 1216 | 1196 | yes |  |
| 3x2 | confidential entry | min | yes | 2086 | 11 | 1 | - | 1604 | 1619 | yes |  |
| 3x2 | confidential entry | full | yes | 2641 | 21 | 3 | 3 | 1691 | 1664 | yes |  |
| 3x2 | confidential entry | full+spl | yes | 3009 | 28 | 3 | - | 1823 | 1668 | yes |  |
| 3x2 | confidential entry | full+data | yes | 2841 | 21 | 3 | - | 1891 | 1860 | yes |  |
| 3x2 | confidential entry | full+reply | yes | 2641 | 21 | 3 | - | 1691 | 1664 | yes |  |
| 3x2 | confidential entry | full+2tree | yes | 2679 | 22 | 3 | - | 1696 | 1668 | yes |  |
| 3x2 | anonymous entry | min | yes | 2245 | 11 | 1 | - | 1764 | 1778 | yes |  |
| 3x2 | anonymous entry | full | yes | 2672 | 17 | 2 | 3 | 1915 | 1897 | yes |  |
| 3x2 | anonymous entry | full+spl | yes | 3040 | 24 | 2 | - | 2047 | 1901 | yes |  |
| 3x2 | anonymous entry | full+data | yes | 2872 | 17 | 2 | - | 2115 | 2093 | yes |  |
| 3x2 | anonymous entry | full+reply | yes | 2771 | 17 | 2 | - | 2014 | 1994 | yes |  |
| 3x2 | anonymous entry | full+2tree | yes | 2710 | 18 | 2 | - | 1920 | 1901 | yes |  |
| 3x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x4 | confidential signer | min | yes | 1912 | 11 | 1 | - | 1430 | 1517 | yes |  |
| 3x4 | confidential signer | full | yes | 2467 | 21 | 3 | 3 | 1517 | 1562 | yes |  |
| 3x4 | confidential signer | full+spl | yes | 2835 | 28 | 3 | - | 1649 | 1566 | yes |  |
| 3x4 | confidential signer | full+data | yes | 2865 | 21 | 3 | - | 1915 | 1952 | yes |  |
| 3x4 | confidential signer | full+reply | yes | 2467 | 21 | 3 | - | 1517 | 1562 | yes |  |
| 3x4 | confidential signer | full+2tree | yes | 2505 | 22 | 3 | - | 1522 | 1566 | yes |  |
| 3x4 | confidential in-proof | min | yes | 2007 | 11 | 1 | - | 1526 | 1614 | yes |  |
| 3x4 | confidential in-proof | full | yes | 2466 | 20 | 2 | 3 | 1613 | 1659 | yes |  |
| 3x4 | confidential in-proof | full+spl | yes | 2834 | 27 | 2 | - | 1745 | 1663 | yes |  |
| 3x4 | confidential in-proof | full+data | yes | 2864 | 20 | 2 | - | 2011 | 2049 | yes |  |
| 3x4 | confidential in-proof | full+reply | yes | 2466 | 20 | 2 | - | 1613 | 1659 | yes |  |
| 3x4 | confidential in-proof | full+2tree | yes | 2504 | 21 | 2 | - | 1618 | 1663 | yes |  |
| 3x4 | anonymous hidden | min | yes | 2103 | 11 | 1 | - | 1622 | 1740 | yes |  |
| 3x4 | anonymous hidden | full | yes | 2530 | 17 | 2 | 3 | 1773 | 1859 | yes |  |
| 3x4 | anonymous hidden | full+spl | yes | 2898 | 24 | 2 | - | 1905 | 1863 | yes |  |
| 3x4 | anonymous hidden | full+data | yes | 2928 | 17 | 2 | - | 2171 | 2249 | yes |  |
| 3x4 | anonymous hidden | full+reply | yes | 2823 | 17 | 2 | - | 2066 | 2150 | yes |  |
| 3x4 | anonymous hidden | full+2tree | yes | 2568 | 18 | 2 | - | 1778 | 1863 | yes |  |
| 3x4 | anonymous public owners | min | yes | 2040 | 11 | 1 | - | 1558 | 1643 | yes |  |
| 3x4 | anonymous public owners | full | yes | 2659 | 21 | 3 | 3 | 1709 | 1762 | yes |  |
| 3x4 | anonymous public owners | full+spl | yes | 3027 | 28 | 3 | - | 1841 | 1766 | yes |  |
| 3x4 | anonymous public owners | full+data | yes | 3057 | 21 | 3 | - | 2107 | 2152 | yes |  |
| 3x4 | anonymous public owners | full+reply | yes | 2952 | 21 | 3 | - | 2002 | 2053 | yes |  |
| 3x4 | anonymous public owners | full+2tree | yes | 2697 | 22 | 3 | - | 1714 | 1766 | yes |  |
| 3x4 | confidential entry | min | yes | 2520 | 11 | 1 | - | 2038 | 2125 | yes |  |
| 3x4 | confidential entry | full | yes | 3075 | 21 | 3 | 3 | 2125 | 2170 | yes |  |
| 3x4 | confidential entry | full+spl | yes | 3443 | 28 | 3 | - | 2257 | 2174 | yes |  |
| 3x4 | confidential entry | full+data | yes | 3473 | 21 | 3 | - | 2523 | 2560 | yes |  |
| 3x4 | confidential entry | full+reply | yes | 3075 | 21 | 3 | - | 2125 | 2170 | yes |  |
| 3x4 | confidential entry | full+2tree | yes | 3113 | 22 | 3 | - | 2130 | 2174 | yes |  |
| 3x4 | anonymous entry | min | yes | 2743 | 11 | 1 | - | 2262 | 2348 | yes |  |
| 3x4 | anonymous entry | full | yes | 3170 | 17 | 2 | 3 | 2413 | 2467 | yes |  |
| 3x4 | anonymous entry | full+spl | yes | 3538 | 24 | 2 | - | 2545 | 2471 | yes |  |
| 3x4 | anonymous entry | full+data | yes | 3568 | 17 | 2 | - | 2811 | 2857 | yes |  |
| 3x4 | anonymous entry | full+reply | yes | 3463 | 17 | 2 | - | 2706 | 2758 | yes |  |
| 3x4 | anonymous entry | full+2tree | yes | 3208 | 18 | 2 | - | 2418 | 2471 | yes |  |
| 3x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x16 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x8 | confidential signer | min | yes | 2780 | 11 | 1 | - | 2298 | 2529 | yes |  |
| 3x8 | confidential signer | full | yes | 3335 | 21 | 3 | 3 | 2385 | 2574 | yes |  |
| 3x8 | confidential signer | full+spl | yes | 3703 | 28 | 3 | - | 2517 | 2578 | yes |  |
| 3x8 | confidential signer | full+data | yes | 4129 | 21 | 3 | - | 3179 | 3352 | no | 33 B |
| 3x8 | confidential signer | full+reply | yes | 3335 | 21 | 3 | - | 2385 | 2574 | yes |  |
| 3x8 | confidential signer | full+2tree | yes | 3373 | 22 | 3 | - | 2390 | 2578 | yes |  |
| 3x8 | confidential in-proof | min | yes | 2875 | 11 | 1 | - | 2394 | 2626 | yes |  |
| 3x8 | confidential in-proof | full | yes | 3334 | 20 | 2 | 3 | 2481 | 2671 | yes |  |
| 3x8 | confidential in-proof | full+spl | yes | 3702 | 27 | 2 | - | 2613 | 2675 | yes |  |
| 3x8 | confidential in-proof | full+data | yes | 4128 | 20 | 2 | - | 3275 | 3449 | no | 32 B |
| 3x8 | confidential in-proof | full+reply | yes | 3334 | 20 | 2 | - | 2481 | 2671 | yes |  |
| 3x8 | confidential in-proof | full+2tree | yes | 3372 | 21 | 2 | - | 2486 | 2675 | yes |  |
| 3x8 | anonymous hidden | min | yes | 3099 | 11 | 1 | - | 2618 | 2880 | yes |  |
| 3x8 | anonymous hidden | full | yes | 3526 | 17 | 2 | 3 | 2769 | 2999 | yes |  |
| 3x8 | anonymous hidden | full+spl | yes | 3894 | 24 | 2 | - | 2901 | 3003 | yes |  |
| 3x8 | anonymous hidden | full+data | yes | 4320 | 17 | 2 | - | 3563 | 3777 | no | 224 B |
| 3x8 | anonymous hidden | full+reply | yes | 4207 | 17 | 2 | - | 3450 | 3678 | no | 111 B |
| 3x8 | anonymous hidden | full+2tree | yes | 3564 | 18 | 2 | - | 2774 | 3003 | yes |  |
| 3x8 | anonymous public owners | min | yes | 3036 | 11 | 1 | - | 2554 | 2783 | yes |  |
| 3x8 | anonymous public owners | full | yes | 3655 | 21 | 3 | 3 | 2705 | 2902 | yes |  |
| 3x8 | anonymous public owners | full+spl | yes | 4023 | 28 | 3 | - | 2837 | 2906 | yes |  |
| 3x8 | anonymous public owners | full+data | yes | 4449 | 21 | 3 | - | 3499 | 3680 | no | 353 B |
| 3x8 | anonymous public owners | full+reply | yes | 4336 | 21 | 3 | - | 3386 | 3581 | no | 240 B |
| 3x8 | anonymous public owners | full+2tree | yes | 3693 | 22 | 3 | - | 2710 | 2906 | yes |  |
| 3x8 | confidential entry | min | yes | 3388 | 11 | 1 | - | 2906 | 3137 | yes |  |
| 3x8 | confidential entry | full | yes | 3943 | 21 | 3 | 2 | 2993 | 3182 | yes |  |
| 3x8 | confidential entry | full+spl | yes | 4311 | 28 | 3 | - | 3125 | 3186 | no | 215 B |
| 3x8 | confidential entry | full+data | yes | 4737 | 21 | 3 | - | 3787 | 3960 | no | 641 B |
| 3x8 | confidential entry | full+reply | yes | 3943 | 21 | 3 | - | 2993 | 3182 | yes |  |
| 3x8 | confidential entry | full+2tree | yes | 3981 | 22 | 3 | - | 2998 | 3186 | yes |  |
| 3x8 | anonymous entry | min | yes | 3739 | 11 | 1 | - | 3258 | 3488 | yes |  |
| 3x8 | anonymous entry | full | yes | 4166 | 17 | 2 | none | 3409 | 3607 | no | 70 B |
| 3x8 | anonymous entry | full+spl | yes | 4534 | 24 | 2 | - | 3541 | 3611 | no | 438 B |
| 3x8 | anonymous entry | full+data | yes | 4960 | 17 | 2 | - | 4203 | 4385 | no | 864 B |
| 3x8 | anonymous entry | full+reply | yes | 4847 | 17 | 2 | - | 4090 | 4286 | no | 751 B |
| 3x8 | anonymous entry | full+2tree | yes | 4204 | 18 | 2 | - | 3414 | 3611 | no | 108 B |
| 3x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x2 | confidential signer | min | yes | 1543 | 12 | 1 | - | 1028 | 1044 | yes |  |
| 4x2 | confidential signer | full | yes | 2098 | 22 | 3 | 4 | 1115 | 1089 | yes |  |
| 4x2 | confidential signer | full+spl | yes | 2466 | 29 | 3 | - | 1247 | 1093 | yes |  |
| 4x2 | confidential signer | full+data | yes | 2298 | 22 | 3 | - | 1315 | 1285 | yes |  |
| 4x2 | confidential signer | full+reply | yes | 2098 | 22 | 3 | - | 1115 | 1089 | yes |  |
| 4x2 | confidential signer | full+2tree | yes | 2136 | 23 | 3 | - | 1120 | 1093 | yes |  |
| 4x2 | confidential in-proof | min | yes | 1638 | 12 | 1 | - | 1124 | 1141 | yes |  |
| 4x2 | confidential in-proof | full | yes | 2097 | 21 | 2 | 4 | 1211 | 1186 | yes |  |
| 4x2 | confidential in-proof | full+spl | yes | 2465 | 28 | 2 | - | 1343 | 1190 | yes |  |
| 4x2 | confidential in-proof | full+data | yes | 2297 | 21 | 2 | - | 1411 | 1382 | yes |  |
| 4x2 | confidential in-proof | full+reply | yes | 2097 | 21 | 2 | - | 1211 | 1186 | yes |  |
| 4x2 | confidential in-proof | full+2tree | yes | 2135 | 22 | 2 | - | 1216 | 1190 | yes |  |
| 4x2 | anonymous hidden | min | yes | 1670 | 12 | 1 | - | 1156 | 1203 | yes |  |
| 4x2 | anonymous hidden | full | yes | 2097 | 18 | 2 | 4 | 1307 | 1322 | yes |  |
| 4x2 | anonymous hidden | full+spl | yes | 2465 | 25 | 2 | - | 1439 | 1326 | yes |  |
| 4x2 | anonymous hidden | full+data | yes | 2297 | 18 | 2 | - | 1507 | 1518 | yes |  |
| 4x2 | anonymous hidden | full+reply | yes | 2196 | 18 | 2 | - | 1406 | 1419 | yes |  |
| 4x2 | anonymous hidden | full+2tree | yes | 2135 | 19 | 2 | - | 1312 | 1326 | yes |  |
| 4x2 | anonymous public owners | min | yes | 1607 | 12 | 1 | - | 1092 | 1106 | yes |  |
| 4x2 | anonymous public owners | full | yes | 2226 | 22 | 3 | 4 | 1243 | 1225 | yes |  |
| 4x2 | anonymous public owners | full+spl | yes | 2594 | 29 | 3 | - | 1375 | 1229 | yes |  |
| 4x2 | anonymous public owners | full+data | yes | 2426 | 22 | 3 | - | 1443 | 1421 | yes |  |
| 4x2 | anonymous public owners | full+reply | yes | 2325 | 22 | 3 | - | 1342 | 1322 | yes |  |
| 4x2 | anonymous public owners | full+2tree | yes | 2264 | 23 | 3 | - | 1248 | 1229 | yes |  |
| 4x2 | confidential entry | min | yes | 2351 | 12 | 1 | - | 1836 | 1852 | yes |  |
| 4x2 | confidential entry | full | yes | 2906 | 22 | 3 | 4 | 1923 | 1897 | yes |  |
| 4x2 | confidential entry | full+spl | yes | 3274 | 29 | 3 | - | 2055 | 1901 | yes |  |
| 4x2 | confidential entry | full+data | yes | 3106 | 22 | 3 | - | 2123 | 2093 | yes |  |
| 4x2 | confidential entry | full+reply | yes | 2906 | 22 | 3 | - | 1923 | 1897 | yes |  |
| 4x2 | confidential entry | full+2tree | yes | 2944 | 23 | 3 | - | 1928 | 1901 | yes |  |
| 4x2 | anonymous entry | min | yes | 2510 | 12 | 1 | - | 1996 | 2011 | yes |  |
| 4x2 | anonymous entry | full | yes | 2937 | 18 | 2 | 4 | 2147 | 2130 | yes |  |
| 4x2 | anonymous entry | full+spl | yes | 3305 | 25 | 2 | - | 2279 | 2134 | yes |  |
| 4x2 | anonymous entry | full+data | yes | 3137 | 18 | 2 | - | 2347 | 2326 | yes |  |
| 4x2 | anonymous entry | full+reply | yes | 3036 | 18 | 2 | - | 2246 | 2227 | yes |  |
| 4x2 | anonymous entry | full+2tree | yes | 2975 | 19 | 2 | - | 2152 | 2134 | yes |  |
| 4x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x4 | confidential signer | min | yes | 1977 | 12 | 1 | - | 1462 | 1550 | yes |  |
| 4x4 | confidential signer | full | yes | 2532 | 22 | 3 | 4 | 1549 | 1595 | yes |  |
| 4x4 | confidential signer | full+spl | yes | 2900 | 29 | 3 | - | 1681 | 1599 | yes |  |
| 4x4 | confidential signer | full+data | yes | 2930 | 22 | 3 | - | 1947 | 1985 | yes |  |
| 4x4 | confidential signer | full+reply | yes | 2532 | 22 | 3 | - | 1549 | 1595 | yes |  |
| 4x4 | confidential signer | full+2tree | yes | 2570 | 23 | 3 | - | 1554 | 1599 | yes |  |
| 4x4 | confidential in-proof | min | yes | 2072 | 12 | 1 | - | 1558 | 1647 | yes |  |
| 4x4 | confidential in-proof | full | yes | 2531 | 21 | 2 | 4 | 1645 | 1692 | yes |  |
| 4x4 | confidential in-proof | full+spl | yes | 2899 | 28 | 2 | - | 1777 | 1696 | yes |  |
| 4x4 | confidential in-proof | full+data | yes | 2929 | 21 | 2 | - | 2043 | 2082 | yes |  |
| 4x4 | confidential in-proof | full+reply | yes | 2531 | 21 | 2 | - | 1645 | 1692 | yes |  |
| 4x4 | confidential in-proof | full+2tree | yes | 2569 | 22 | 2 | - | 1650 | 1696 | yes |  |
| 4x4 | anonymous hidden | min | yes | 2168 | 12 | 1 | - | 1654 | 1773 | yes |  |
| 4x4 | anonymous hidden | full | yes | 2595 | 18 | 2 | 4 | 1805 | 1892 | yes |  |
| 4x4 | anonymous hidden | full+spl | yes | 2963 | 25 | 2 | - | 1937 | 1896 | yes |  |
| 4x4 | anonymous hidden | full+data | yes | 2993 | 18 | 2 | - | 2203 | 2282 | yes |  |
| 4x4 | anonymous hidden | full+reply | yes | 2888 | 18 | 2 | - | 2098 | 2183 | yes |  |
| 4x4 | anonymous hidden | full+2tree | yes | 2633 | 19 | 2 | - | 1810 | 1896 | yes |  |
| 4x4 | anonymous public owners | min | yes | 2105 | 12 | 1 | - | 1590 | 1676 | yes |  |
| 4x4 | anonymous public owners | full | yes | 2724 | 22 | 3 | 4 | 1741 | 1795 | yes |  |
| 4x4 | anonymous public owners | full+spl | yes | 3092 | 29 | 3 | - | 1873 | 1799 | yes |  |
| 4x4 | anonymous public owners | full+data | yes | 3122 | 22 | 3 | - | 2139 | 2185 | yes |  |
| 4x4 | anonymous public owners | full+reply | yes | 3017 | 22 | 3 | - | 2034 | 2086 | yes |  |
| 4x4 | anonymous public owners | full+2tree | yes | 2762 | 23 | 3 | - | 1746 | 1799 | yes |  |
| 4x4 | confidential entry | min | yes | 2785 | 12 | 1 | - | 2270 | 2358 | yes |  |
| 4x4 | confidential entry | full | yes | 3340 | 22 | 3 | 4 | 2357 | 2403 | yes |  |
| 4x4 | confidential entry | full+spl | yes | 3708 | 29 | 3 | - | 2489 | 2407 | yes |  |
| 4x4 | confidential entry | full+data | yes | 3738 | 22 | 3 | - | 2755 | 2793 | yes |  |
| 4x4 | confidential entry | full+reply | yes | 3340 | 22 | 3 | - | 2357 | 2403 | yes |  |
| 4x4 | confidential entry | full+2tree | yes | 3378 | 23 | 3 | - | 2362 | 2407 | yes |  |
| 4x4 | anonymous entry | min | yes | 3008 | 12 | 1 | - | 2494 | 2581 | yes |  |
| 4x4 | anonymous entry | full | yes | 3435 | 18 | 2 | 4 | 2645 | 2700 | yes |  |
| 4x4 | anonymous entry | full+spl | yes | 3803 | 25 | 2 | - | 2777 | 2704 | yes |  |
| 4x4 | anonymous entry | full+data | yes | 3833 | 18 | 2 | - | 3043 | 3090 | yes |  |
| 4x4 | anonymous entry | full+reply | yes | 3728 | 18 | 2 | - | 2938 | 2991 | yes |  |
| 4x4 | anonymous entry | full+2tree | yes | 3473 | 19 | 2 | - | 2650 | 2704 | yes |  |
| 4x4 | delegate | min | yes | 1977 | 12 | 1 | - | 1462 | 1550 | yes |  |
| 4x4 | delegate | full | yes | 2320 | 18 | 2 | - | 1533 | 1595 | yes |  |
| 4x4 | delegate | full+spl | yes | 2560 | 25 | 2 | - | 1537 | 1599 | yes |  |
| 4x4 | delegate | full+data | yes | 2718 | 18 | 2 | - | 1931 | 1985 | yes |  |
| 4x4 | delegate | full+reply | yes | 2320 | 18 | 2 | - | 1533 | 1595 | yes |  |
| 4x4 | delegate | full+2tree | yes | 2358 | 19 | 2 | - | 1538 | 1599 | yes |  |
| 4x4 | anonymous delegate | min | yes | 2105 | 12 | 1 | - | 1590 | 1676 | yes |  |
| 4x4 | anonymous delegate | full | yes | 2512 | 18 | 2 | - | 1725 | 1795 | yes |  |
| 4x4 | anonymous delegate | full+spl | yes | 2752 | 25 | 2 | - | 1729 | 1799 | yes |  |
| 4x4 | anonymous delegate | full+data | yes | 2910 | 18 | 2 | - | 2123 | 2185 | yes |  |
| 4x4 | anonymous delegate | full+reply | yes | 2805 | 18 | 2 | - | 2018 | 2086 | yes |  |
| 4x4 | anonymous delegate | full+2tree | yes | 2550 | 19 | 2 | - | 1730 | 1799 | yes |  |
| 4x8 | confidential signer | min | yes | 2845 | 12 | 1 | - | 2330 | 2562 | yes |  |
| 4x8 | confidential signer | full | yes | 3400 | 22 | 3 | 4 | 2417 | 2607 | yes |  |
| 4x8 | confidential signer | full+spl | yes | 3768 | 29 | 3 | - | 2549 | 2611 | yes |  |
| 4x8 | confidential signer | full+data | yes | 4194 | 22 | 3 | - | 3211 | 3385 | no | 98 B |
| 4x8 | confidential signer | full+reply | yes | 3400 | 22 | 3 | - | 2417 | 2607 | yes |  |
| 4x8 | confidential signer | full+2tree | yes | 3438 | 23 | 3 | - | 2422 | 2611 | yes |  |
| 4x8 | confidential in-proof | min | yes | 2940 | 12 | 1 | - | 2426 | 2659 | yes |  |
| 4x8 | confidential in-proof | full | yes | 3399 | 21 | 2 | 4 | 2513 | 2704 | yes |  |
| 4x8 | confidential in-proof | full+spl | yes | 3767 | 28 | 2 | - | 2645 | 2708 | yes |  |
| 4x8 | confidential in-proof | full+data | yes | 4193 | 21 | 2 | - | 3307 | 3482 | no | 97 B |
| 4x8 | confidential in-proof | full+reply | yes | 3399 | 21 | 2 | - | 2513 | 2704 | yes |  |
| 4x8 | confidential in-proof | full+2tree | yes | 3437 | 22 | 2 | - | 2518 | 2708 | yes |  |
| 4x8 | anonymous hidden | min | yes | 3164 | 12 | 1 | - | 2650 | 2913 | yes |  |
| 4x8 | anonymous hidden | full | yes | 3591 | 18 | 2 | 4 | 2801 | 3032 | yes |  |
| 4x8 | anonymous hidden | full+spl | yes | 3959 | 25 | 2 | - | 2933 | 3036 | yes |  |
| 4x8 | anonymous hidden | full+data | yes | 4385 | 18 | 2 | - | 3595 | 3810 | no | 289 B |
| 4x8 | anonymous hidden | full+reply | yes | 4272 | 18 | 2 | - | 3482 | 3711 | no | 176 B |
| 4x8 | anonymous hidden | full+2tree | yes | 3629 | 19 | 2 | - | 2806 | 3036 | yes |  |
| 4x8 | anonymous public owners | min | yes | 3101 | 12 | 1 | - | 2586 | 2816 | yes |  |
| 4x8 | anonymous public owners | full | yes | 3720 | 22 | 3 | 4 | 2737 | 2935 | yes |  |
| 4x8 | anonymous public owners | full+spl | yes | 4088 | 29 | 3 | - | 2869 | 2939 | yes |  |
| 4x8 | anonymous public owners | full+data | yes | 4514 | 22 | 3 | - | 3531 | 3713 | no | 418 B |
| 4x8 | anonymous public owners | full+reply | yes | 4401 | 22 | 3 | - | 3418 | 3614 | no | 305 B |
| 4x8 | anonymous public owners | full+2tree | yes | 3758 | 23 | 3 | - | 2742 | 2939 | yes |  |
| 4x8 | confidential entry | min | yes | 3653 | 12 | 1 | - | 3138 | 3370 | yes |  |
| 4x8 | confidential entry | full | yes | 4208 | 22 | 3 | none | 3225 | 3415 | no | 112 B |
| 4x8 | confidential entry | full+spl | yes | 4576 | 29 | 3 | - | 3357 | 3419 | no | 480 B |
| 4x8 | confidential entry | full+data | yes | 5002 | 22 | 3 | - | 4019 | 4193 | no | 906 B |
| 4x8 | confidential entry | full+reply | yes | 4208 | 22 | 3 | - | 3225 | 3415 | no | 112 B |
| 4x8 | confidential entry | full+2tree | yes | 4246 | 23 | 3 | - | 3230 | 3419 | no | 150 B |
| 4x8 | anonymous entry | min | yes | 4004 | 12 | 1 | - | 3490 | 3721 | yes |  |
| 4x8 | anonymous entry | full | yes | 4431 | 18 | 2 | none | 3641 | 3840 | no | 335 B |
| 4x8 | anonymous entry | full+spl | yes | 4799 | 25 | 2 | - | 3773 | 3844 | no | 703 B |
| 4x8 | anonymous entry | full+data | yes | 5225 | 18 | 2 | - | 4435 | 4618 | no | 1129 B |
| 4x8 | anonymous entry | full+reply | yes | 5112 | 18 | 2 | - | 4322 | 4519 | no | 1016 B |
| 4x8 | anonymous entry | full+2tree | yes | 4469 | 19 | 2 | - | 3646 | 3844 | no | 373 B |
| 4x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x2 | confidential signer | min | yes | 1608 | 13 | 1 | - | 1060 | 1077 | yes |  |
| 5x2 | confidential signer | full | yes | 2163 | 23 | 3 | 5 | 1147 | 1122 | yes |  |
| 5x2 | confidential signer | full+spl | yes | 2531 | 30 | 3 | - | 1279 | 1126 | yes |  |
| 5x2 | confidential signer | full+data | yes | 2363 | 23 | 3 | - | 1347 | 1318 | yes |  |
| 5x2 | confidential signer | full+reply | yes | 2163 | 23 | 3 | - | 1147 | 1122 | yes |  |
| 5x2 | confidential signer | full+2tree | yes | 2201 | 24 | 3 | - | 1152 | 1126 | yes |  |
| 5x2 | confidential in-proof | min | yes | 1703 | 13 | 1 | - | 1156 | 1174 | yes |  |
| 5x2 | confidential in-proof | full | yes | 2162 | 22 | 2 | 5 | 1243 | 1219 | yes |  |
| 5x2 | confidential in-proof | full+spl | yes | 2530 | 29 | 2 | - | 1375 | 1223 | yes |  |
| 5x2 | confidential in-proof | full+data | yes | 2362 | 22 | 2 | - | 1443 | 1415 | yes |  |
| 5x2 | confidential in-proof | full+reply | yes | 2162 | 22 | 2 | - | 1243 | 1219 | yes |  |
| 5x2 | confidential in-proof | full+2tree | yes | 2200 | 23 | 2 | - | 1248 | 1223 | yes |  |
| 5x2 | anonymous hidden | min | yes | 1735 | 13 | 1 | - | 1188 | 1236 | yes |  |
| 5x2 | anonymous hidden | full | yes | 2162 | 19 | 2 | 5 | 1339 | 1355 | yes |  |
| 5x2 | anonymous hidden | full+spl | yes | 2530 | 26 | 2 | - | 1471 | 1359 | yes |  |
| 5x2 | anonymous hidden | full+data | yes | 2362 | 19 | 2 | - | 1539 | 1551 | yes |  |
| 5x2 | anonymous hidden | full+reply | yes | 2261 | 19 | 2 | - | 1438 | 1452 | yes |  |
| 5x2 | anonymous hidden | full+2tree | yes | 2200 | 20 | 2 | - | 1344 | 1359 | yes |  |
| 5x2 | anonymous public owners | min | yes | 1672 | 13 | 1 | - | 1124 | 1139 | yes |  |
| 5x2 | anonymous public owners | full | yes | 2291 | 23 | 3 | 5 | 1275 | 1258 | yes |  |
| 5x2 | anonymous public owners | full+spl | yes | 2659 | 30 | 3 | - | 1407 | 1262 | yes |  |
| 5x2 | anonymous public owners | full+data | yes | 2491 | 23 | 3 | - | 1475 | 1454 | yes |  |
| 5x2 | anonymous public owners | full+reply | yes | 2390 | 23 | 3 | - | 1374 | 1355 | yes |  |
| 5x2 | anonymous public owners | full+2tree | yes | 2329 | 24 | 3 | - | 1280 | 1262 | yes |  |
| 5x2 | confidential entry | min | yes | 2616 | 13 | 1 | - | 2068 | 2085 | yes |  |
| 5x2 | confidential entry | full | yes | 3171 | 23 | 3 | 5 | 2155 | 2130 | yes |  |
| 5x2 | confidential entry | full+spl | yes | 3539 | 30 | 3 | - | 2287 | 2134 | yes |  |
| 5x2 | confidential entry | full+data | yes | 3371 | 23 | 3 | - | 2355 | 2326 | yes |  |
| 5x2 | confidential entry | full+reply | yes | 3171 | 23 | 3 | - | 2155 | 2130 | yes |  |
| 5x2 | confidential entry | full+2tree | yes | 3209 | 24 | 3 | - | 2160 | 2134 | yes |  |
| 5x2 | anonymous entry | min | yes | 2775 | 13 | 1 | - | 2228 | 2244 | yes |  |
| 5x2 | anonymous entry | full | yes | 3202 | 19 | 2 | 5 | 2379 | 2363 | yes |  |
| 5x2 | anonymous entry | full+spl | yes | 3570 | 26 | 2 | - | 2511 | 2367 | yes |  |
| 5x2 | anonymous entry | full+data | yes | 3402 | 19 | 2 | - | 2579 | 2559 | yes |  |
| 5x2 | anonymous entry | full+reply | yes | 3301 | 19 | 2 | - | 2478 | 2460 | yes |  |
| 5x2 | anonymous entry | full+2tree | yes | 3240 | 20 | 2 | - | 2384 | 2367 | yes |  |
| 5x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x4 | confidential signer | min | yes | 2042 | 13 | 1 | - | 1494 | 1583 | yes |  |
| 5x4 | confidential signer | full | yes | 2597 | 23 | 3 | 5 | 1581 | 1628 | yes |  |
| 5x4 | confidential signer | full+spl | yes | 2965 | 30 | 3 | - | 1713 | 1632 | yes |  |
| 5x4 | confidential signer | full+data | yes | 2995 | 23 | 3 | - | 1979 | 2018 | yes |  |
| 5x4 | confidential signer | full+reply | yes | 2597 | 23 | 3 | - | 1581 | 1628 | yes |  |
| 5x4 | confidential signer | full+2tree | yes | 2635 | 24 | 3 | - | 1586 | 1632 | yes |  |
| 5x4 | confidential in-proof | min | yes | 2137 | 13 | 1 | - | 1590 | 1680 | yes |  |
| 5x4 | confidential in-proof | full | yes | 2596 | 22 | 2 | 5 | 1677 | 1725 | yes |  |
| 5x4 | confidential in-proof | full+spl | yes | 2964 | 29 | 2 | - | 1809 | 1729 | yes |  |
| 5x4 | confidential in-proof | full+data | yes | 2994 | 22 | 2 | - | 2075 | 2115 | yes |  |
| 5x4 | confidential in-proof | full+reply | yes | 2596 | 22 | 2 | - | 1677 | 1725 | yes |  |
| 5x4 | confidential in-proof | full+2tree | yes | 2634 | 23 | 2 | - | 1682 | 1729 | yes |  |
| 5x4 | anonymous hidden | min | yes | 2233 | 13 | 1 | - | 1686 | 1806 | yes |  |
| 5x4 | anonymous hidden | full | yes | 2660 | 19 | 2 | 5 | 1837 | 1925 | yes |  |
| 5x4 | anonymous hidden | full+spl | yes | 3028 | 26 | 2 | - | 1969 | 1929 | yes |  |
| 5x4 | anonymous hidden | full+data | yes | 3058 | 19 | 2 | - | 2235 | 2315 | yes |  |
| 5x4 | anonymous hidden | full+reply | yes | 2953 | 19 | 2 | - | 2130 | 2216 | yes |  |
| 5x4 | anonymous hidden | full+2tree | yes | 2698 | 20 | 2 | - | 1842 | 1929 | yes |  |
| 5x4 | anonymous public owners | min | yes | 2170 | 13 | 1 | - | 1622 | 1709 | yes |  |
| 5x4 | anonymous public owners | full | yes | 2789 | 23 | 3 | 5 | 1773 | 1828 | yes |  |
| 5x4 | anonymous public owners | full+spl | yes | 3157 | 30 | 3 | - | 1905 | 1832 | yes |  |
| 5x4 | anonymous public owners | full+data | yes | 3187 | 23 | 3 | - | 2171 | 2218 | yes |  |
| 5x4 | anonymous public owners | full+reply | yes | 3082 | 23 | 3 | - | 2066 | 2119 | yes |  |
| 5x4 | anonymous public owners | full+2tree | yes | 2827 | 24 | 3 | - | 1778 | 1832 | yes |  |
| 5x4 | confidential entry | min | yes | 3050 | 13 | 1 | - | 2502 | 2591 | yes |  |
| 5x4 | confidential entry | full | yes | 3605 | 23 | 3 | 5 | 2589 | 2636 | yes |  |
| 5x4 | confidential entry | full+spl | yes | 3973 | 30 | 3 | - | 2721 | 2640 | yes |  |
| 5x4 | confidential entry | full+data | yes | 4003 | 23 | 3 | - | 2987 | 3026 | yes |  |
| 5x4 | confidential entry | full+reply | yes | 3605 | 23 | 3 | - | 2589 | 2636 | yes |  |
| 5x4 | confidential entry | full+2tree | yes | 3643 | 24 | 3 | - | 2594 | 2640 | yes |  |
| 5x4 | anonymous entry | min | yes | 3273 | 13 | 1 | - | 2726 | 2814 | yes |  |
| 5x4 | anonymous entry | full | yes | 3700 | 19 | 2 | 4 | 2877 | 2933 | yes |  |
| 5x4 | anonymous entry | full+spl | yes | 4068 | 26 | 2 | - | 3009 | 2937 | yes |  |
| 5x4 | anonymous entry | full+data | yes | 4098 | 19 | 2 | - | 3275 | 3323 | no | 2 B |
| 5x4 | anonymous entry | full+reply | yes | 3993 | 19 | 2 | - | 3170 | 3224 | yes |  |
| 5x4 | anonymous entry | full+2tree | yes | 3738 | 20 | 2 | - | 2882 | 2937 | yes |  |
| 5x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x16 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x8 | confidential signer | min | yes | 2910 | 13 | 1 | - | 2362 | 2595 | yes |  |
| 5x8 | confidential signer | full | yes | 3465 | 23 | 3 | 5 | 2449 | 2640 | yes |  |
| 5x8 | confidential signer | full+spl | yes | 3833 | 30 | 3 | - | 2581 | 2644 | yes |  |
| 5x8 | confidential signer | full+data | yes | 4259 | 23 | 3 | - | 3243 | 3418 | no | 163 B |
| 5x8 | confidential signer | full+reply | yes | 3465 | 23 | 3 | - | 2449 | 2640 | yes |  |
| 5x8 | confidential signer | full+2tree | yes | 3503 | 24 | 3 | - | 2454 | 2644 | yes |  |
| 5x8 | confidential in-proof | min | yes | 3005 | 13 | 1 | - | 2458 | 2692 | yes |  |
| 5x8 | confidential in-proof | full | yes | 3464 | 22 | 2 | 5 | 2545 | 2737 | yes |  |
| 5x8 | confidential in-proof | full+spl | yes | 3832 | 29 | 2 | - | 2677 | 2741 | yes |  |
| 5x8 | confidential in-proof | full+data | yes | 4258 | 22 | 2 | - | 3339 | 3515 | no | 162 B |
| 5x8 | confidential in-proof | full+reply | yes | 3464 | 22 | 2 | - | 2545 | 2737 | yes |  |
| 5x8 | confidential in-proof | full+2tree | yes | 3502 | 23 | 2 | - | 2550 | 2741 | yes |  |
| 5x8 | anonymous hidden | min | yes | 3229 | 13 | 1 | - | 2682 | 2946 | yes |  |
| 5x8 | anonymous hidden | full | yes | 3656 | 19 | 2 | 4 | 2833 | 3065 | yes |  |
| 5x8 | anonymous hidden | full+spl | yes | 4024 | 26 | 2 | - | 2965 | 3069 | yes |  |
| 5x8 | anonymous hidden | full+data | yes | 4450 | 19 | 2 | - | 3627 | 3843 | no | 354 B |
| 5x8 | anonymous hidden | full+reply | yes | 4337 | 19 | 2 | - | 3514 | 3744 | no | 241 B |
| 5x8 | anonymous hidden | full+2tree | yes | 3694 | 20 | 2 | - | 2838 | 3069 | yes |  |
| 5x8 | anonymous public owners | min | yes | 3166 | 13 | 1 | - | 2618 | 2849 | yes |  |
| 5x8 | anonymous public owners | full | yes | 3785 | 23 | 3 | 4 | 2769 | 2968 | yes |  |
| 5x8 | anonymous public owners | full+spl | yes | 4153 | 30 | 3 | - | 2901 | 2972 | no | 57 B |
| 5x8 | anonymous public owners | full+data | yes | 4579 | 23 | 3 | - | 3563 | 3746 | no | 483 B |
| 5x8 | anonymous public owners | full+reply | yes | 4466 | 23 | 3 | - | 3450 | 3647 | no | 370 B |
| 5x8 | anonymous public owners | full+2tree | yes | 3823 | 24 | 3 | - | 2774 | 2972 | yes |  |
| 5x8 | confidential entry | min | yes | 3918 | 13 | 1 | - | 3370 | 3603 | yes |  |
| 5x8 | confidential entry | full | yes | 4473 | 23 | 3 | none | 3457 | 3648 | no | 377 B |
| 5x8 | confidential entry | full+spl | yes | 4841 | 30 | 3 | - | 3589 | 3652 | no | 745 B |
| 5x8 | confidential entry | full+data | yes | 5267 | 23 | 3 | - | 4251 | 4426 | no | 1171 B |
| 5x8 | confidential entry | full+reply | yes | 4473 | 23 | 3 | - | 3457 | 3648 | no | 377 B |
| 5x8 | confidential entry | full+2tree | yes | 4511 | 24 | 3 | - | 3462 | 3652 | no | 415 B |
| 5x8 | anonymous entry | min | yes | 4269 | 13 | 1 | - | 3722 | 3954 | no | 173 B |
| 5x8 | anonymous entry | full | yes | 4696 | 19 | 2 | none | 3873 | 4073 | no | 600 B |
| 5x8 | anonymous entry | full+spl | yes | 5064 | 26 | 2 | - | 4005 | 4077 | no | 968 B |
| 5x8 | anonymous entry | full+data | yes | 5490 | 19 | 2 | - | 4667 | 4851 | no | 1394 B |
| 5x8 | anonymous entry | full+reply | yes | 5377 | 19 | 2 | - | 4554 | 4752 | no | 1281 B |
| 5x8 | anonymous entry | full+2tree | yes | 4734 | 20 | 2 | - | 3878 | 4077 | no | 638 B |
| 5x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x2 | confidential signer | min | yes | 1673 | 14 | 1 | - | 1092 | 1110 | yes |  |
| 6x2 | confidential signer | full | yes | 2228 | 24 | 3 | 6 | 1179 | 1155 | yes |  |
| 6x2 | confidential signer | full+spl | yes | 2596 | 31 | 3 | - | 1311 | 1159 | yes |  |
| 6x2 | confidential signer | full+data | yes | 2428 | 24 | 3 | - | 1379 | 1351 | yes |  |
| 6x2 | confidential signer | full+reply | yes | 2228 | 24 | 3 | - | 1179 | 1155 | yes |  |
| 6x2 | confidential signer | full+2tree | yes | 2266 | 25 | 3 | - | 1184 | 1159 | yes |  |
| 6x2 | confidential in-proof | min | yes | 1768 | 14 | 1 | - | 1188 | 1207 | yes |  |
| 6x2 | confidential in-proof | full | yes | 2227 | 23 | 2 | 6 | 1275 | 1252 | yes |  |
| 6x2 | confidential in-proof | full+spl | yes | 2595 | 30 | 2 | - | 1407 | 1256 | yes |  |
| 6x2 | confidential in-proof | full+data | yes | 2427 | 23 | 2 | - | 1475 | 1448 | yes |  |
| 6x2 | confidential in-proof | full+reply | yes | 2227 | 23 | 2 | - | 1275 | 1252 | yes |  |
| 6x2 | confidential in-proof | full+2tree | yes | 2265 | 24 | 2 | - | 1280 | 1256 | yes |  |
| 6x2 | anonymous hidden | min | yes | 1800 | 14 | 1 | - | 1220 | 1269 | yes |  |
| 6x2 | anonymous hidden | full | yes | 2227 | 20 | 2 | 6 | 1371 | 1388 | yes |  |
| 6x2 | anonymous hidden | full+spl | yes | 2595 | 27 | 2 | - | 1503 | 1392 | yes |  |
| 6x2 | anonymous hidden | full+data | yes | 2427 | 20 | 2 | - | 1571 | 1584 | yes |  |
| 6x2 | anonymous hidden | full+reply | yes | 2326 | 20 | 2 | - | 1470 | 1485 | yes |  |
| 6x2 | anonymous hidden | full+2tree | yes | 2265 | 21 | 2 | - | 1376 | 1392 | yes |  |
| 6x2 | anonymous public owners | min | yes | 1737 | 14 | 1 | - | 1156 | 1172 | yes |  |
| 6x2 | anonymous public owners | full | yes | 2356 | 24 | 3 | 6 | 1307 | 1291 | yes |  |
| 6x2 | anonymous public owners | full+spl | yes | 2724 | 31 | 3 | - | 1439 | 1295 | yes |  |
| 6x2 | anonymous public owners | full+data | yes | 2556 | 24 | 3 | - | 1507 | 1487 | yes |  |
| 6x2 | anonymous public owners | full+reply | yes | 2455 | 24 | 3 | - | 1406 | 1388 | yes |  |
| 6x2 | anonymous public owners | full+2tree | yes | 2394 | 25 | 3 | - | 1312 | 1295 | yes |  |
| 6x2 | confidential entry | min | yes | 2881 | 14 | 1 | - | 2300 | 2318 | yes |  |
| 6x2 | confidential entry | full | yes | 3436 | 24 | 3 | 6 | 2387 | 2363 | yes |  |
| 6x2 | confidential entry | full+spl | yes | 3804 | 31 | 3 | - | 2519 | 2367 | yes |  |
| 6x2 | confidential entry | full+data | yes | 3636 | 24 | 3 | - | 2587 | 2559 | yes |  |
| 6x2 | confidential entry | full+reply | yes | 3436 | 24 | 3 | - | 2387 | 2363 | yes |  |
| 6x2 | confidential entry | full+2tree | yes | 3474 | 25 | 3 | - | 2392 | 2367 | yes |  |
| 6x2 | anonymous entry | min | yes | 3040 | 14 | 1 | - | 2460 | 2477 | yes |  |
| 6x2 | anonymous entry | full | yes | 3467 | 20 | 2 | 6 | 2611 | 2596 | yes |  |
| 6x2 | anonymous entry | full+spl | yes | 3835 | 27 | 2 | - | 2743 | 2600 | yes |  |
| 6x2 | anonymous entry | full+data | yes | 3667 | 20 | 2 | - | 2811 | 2792 | yes |  |
| 6x2 | anonymous entry | full+reply | yes | 3566 | 20 | 2 | - | 2710 | 2693 | yes |  |
| 6x2 | anonymous entry | full+2tree | yes | 3505 | 21 | 2 | - | 2616 | 2600 | yes |  |
| 6x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x4 | confidential signer | min | yes | 2107 | 14 | 1 | - | 1526 | 1616 | yes |  |
| 6x4 | confidential signer | full | yes | 2662 | 24 | 3 | 6 | 1613 | 1661 | yes |  |
| 6x4 | confidential signer | full+spl | yes | 3030 | 31 | 3 | - | 1745 | 1665 | yes |  |
| 6x4 | confidential signer | full+data | yes | 3060 | 24 | 3 | - | 2011 | 2051 | yes |  |
| 6x4 | confidential signer | full+reply | yes | 2662 | 24 | 3 | - | 1613 | 1661 | yes |  |
| 6x4 | confidential signer | full+2tree | yes | 2700 | 25 | 3 | - | 1618 | 1665 | yes |  |
| 6x4 | confidential in-proof | min | yes | 2202 | 14 | 1 | - | 1622 | 1713 | yes |  |
| 6x4 | confidential in-proof | full | yes | 2661 | 23 | 2 | 6 | 1709 | 1758 | yes |  |
| 6x4 | confidential in-proof | full+spl | yes | 3029 | 30 | 2 | - | 1841 | 1762 | yes |  |
| 6x4 | confidential in-proof | full+data | yes | 3059 | 23 | 2 | - | 2107 | 2148 | yes |  |
| 6x4 | confidential in-proof | full+reply | yes | 2661 | 23 | 2 | - | 1709 | 1758 | yes |  |
| 6x4 | confidential in-proof | full+2tree | yes | 2699 | 24 | 2 | - | 1714 | 1762 | yes |  |
| 6x4 | anonymous hidden | min | yes | 2298 | 14 | 1 | - | 1718 | 1839 | yes |  |
| 6x4 | anonymous hidden | full | yes | 2725 | 20 | 2 | 6 | 1869 | 1958 | yes |  |
| 6x4 | anonymous hidden | full+spl | yes | 3093 | 27 | 2 | - | 2001 | 1962 | yes |  |
| 6x4 | anonymous hidden | full+data | yes | 3123 | 20 | 2 | - | 2267 | 2348 | yes |  |
| 6x4 | anonymous hidden | full+reply | yes | 3018 | 20 | 2 | - | 2162 | 2249 | yes |  |
| 6x4 | anonymous hidden | full+2tree | yes | 2763 | 21 | 2 | - | 1874 | 1962 | yes |  |
| 6x4 | anonymous public owners | min | yes | 2235 | 14 | 1 | - | 1654 | 1742 | yes |  |
| 6x4 | anonymous public owners | full | yes | 2854 | 24 | 3 | 6 | 1805 | 1861 | yes |  |
| 6x4 | anonymous public owners | full+spl | yes | 3222 | 31 | 3 | - | 1937 | 1865 | yes |  |
| 6x4 | anonymous public owners | full+data | yes | 3252 | 24 | 3 | - | 2203 | 2251 | yes |  |
| 6x4 | anonymous public owners | full+reply | yes | 3147 | 24 | 3 | - | 2098 | 2152 | yes |  |
| 6x4 | anonymous public owners | full+2tree | yes | 2892 | 25 | 3 | - | 1810 | 1865 | yes |  |
| 6x4 | confidential entry | min | yes | 3315 | 14 | 1 | - | 2734 | 2824 | yes |  |
| 6x4 | confidential entry | full | yes | 3870 | 24 | 3 | 3 | 2821 | 2869 | yes |  |
| 6x4 | confidential entry | full+spl | yes | 4238 | 31 | 3 | - | 2953 | 2873 | no | 142 B |
| 6x4 | confidential entry | full+data | yes | 4268 | 24 | 3 | - | 3219 | 3259 | no | 172 B |
| 6x4 | confidential entry | full+reply | yes | 3870 | 24 | 3 | - | 2821 | 2869 | yes |  |
| 6x4 | confidential entry | full+2tree | yes | 3908 | 25 | 3 | - | 2826 | 2873 | yes |  |
| 6x4 | anonymous entry | min | yes | 3538 | 14 | 1 | - | 2958 | 3047 | yes |  |
| 6x4 | anonymous entry | full | yes | 3965 | 20 | 2 | 1 | 3109 | 3166 | yes |  |
| 6x4 | anonymous entry | full+spl | yes | 4333 | 27 | 2 | - | 3241 | 3170 | no | 237 B |
| 6x4 | anonymous entry | full+data | yes | 4363 | 20 | 2 | - | 3507 | 3556 | no | 267 B |
| 6x4 | anonymous entry | full+reply | yes | 4258 | 20 | 2 | - | 3402 | 3457 | no | 162 B |
| 6x4 | anonymous entry | full+2tree | yes | 4003 | 21 | 2 | - | 3114 | 3170 | yes |  |
| 6x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x16 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x8 | confidential signer | min | yes | 2975 | 14 | 1 | - | 2394 | 2628 | yes |  |
| 6x8 | confidential signer | full | yes | 3530 | 24 | 3 | 6 | 2481 | 2673 | yes |  |
| 6x8 | confidential signer | full+spl | yes | 3898 | 31 | 3 | - | 2613 | 2677 | yes |  |
| 6x8 | confidential signer | full+data | yes | 4324 | 24 | 3 | - | 3275 | 3451 | no | 228 B |
| 6x8 | confidential signer | full+reply | yes | 3530 | 24 | 3 | - | 2481 | 2673 | yes |  |
| 6x8 | confidential signer | full+2tree | yes | 3568 | 25 | 3 | - | 2486 | 2677 | yes |  |
| 6x8 | confidential in-proof | min | yes | 3070 | 14 | 1 | - | 2490 | 2725 | yes |  |
| 6x8 | confidential in-proof | full | yes | 3529 | 23 | 2 | 5 | 2577 | 2770 | yes |  |
| 6x8 | confidential in-proof | full+spl | yes | 3897 | 30 | 2 | - | 2709 | 2774 | yes |  |
| 6x8 | confidential in-proof | full+data | yes | 4323 | 23 | 2 | - | 3371 | 3548 | no | 227 B |
| 6x8 | confidential in-proof | full+reply | yes | 3529 | 23 | 2 | - | 2577 | 2770 | yes |  |
| 6x8 | confidential in-proof | full+2tree | yes | 3567 | 24 | 2 | - | 2582 | 2774 | yes |  |
| 6x8 | anonymous hidden | min | yes | 3294 | 14 | 1 | - | 2714 | 2979 | yes |  |
| 6x8 | anonymous hidden | full | yes | 3721 | 20 | 2 | 3 | 2865 | 3098 | yes |  |
| 6x8 | anonymous hidden | full+spl | yes | 4089 | 27 | 2 | - | 2997 | 3102 | yes |  |
| 6x8 | anonymous hidden | full+data | yes | 4515 | 20 | 2 | - | 3659 | 3876 | no | 419 B |
| 6x8 | anonymous hidden | full+reply | yes | 4402 | 20 | 2 | - | 3546 | 3777 | no | 306 B |
| 6x8 | anonymous hidden | full+2tree | yes | 3759 | 21 | 2 | - | 2870 | 3102 | yes |  |
| 6x8 | anonymous public owners | min | yes | 3231 | 14 | 1 | - | 2650 | 2882 | yes |  |
| 6x8 | anonymous public owners | full | yes | 3850 | 24 | 3 | 3 | 2801 | 3001 | yes |  |
| 6x8 | anonymous public owners | full+spl | yes | 4218 | 31 | 3 | - | 2933 | 3005 | no | 122 B |
| 6x8 | anonymous public owners | full+data | yes | 4644 | 24 | 3 | - | 3595 | 3779 | no | 548 B |
| 6x8 | anonymous public owners | full+reply | yes | 4531 | 24 | 3 | - | 3482 | 3680 | no | 435 B |
| 6x8 | anonymous public owners | full+2tree | yes | 3888 | 25 | 3 | - | 2806 | 3005 | yes |  |
| 6x8 | confidential entry | min | yes | 4183 | 14 | 1 | - | 3602 | 3836 | no | 87 B |
| 6x8 | confidential entry | full | yes | 4738 | 24 | 3 | none | 3689 | 3881 | no | 642 B |
| 6x8 | confidential entry | full+spl | yes | 5106 | 31 | 3 | - | 3821 | 3885 | no | 1010 B |
| 6x8 | confidential entry | full+data | yes | 5532 | 24 | 3 | - | 4483 | 4659 | no | 1436 B |
| 6x8 | confidential entry | full+reply | yes | 4738 | 24 | 3 | - | 3689 | 3881 | no | 642 B |
| 6x8 | confidential entry | full+2tree | yes | 4776 | 25 | 3 | - | 3694 | 3885 | no | 680 B |
| 6x8 | anonymous entry | min | yes | 4534 | 14 | 1 | - | 3954 | 4187 | no | 438 B |
| 6x8 | anonymous entry | full | yes | 4961 | 20 | 2 | none | 4105 | 4306 | no | 865 B |
| 6x8 | anonymous entry | full+spl | yes | 5329 | 27 | 2 | - | 4237 | 4310 | no | 1233 B |
| 6x8 | anonymous entry | full+data | yes | 5755 | 20 | 2 | - | 4899 | 5084 | no | 1659 B |
| 6x8 | anonymous entry | full+reply | yes | 5642 | 20 | 2 | - | 4786 | 4985 | no | 1546 B |
| 6x8 | anonymous entry | full+2tree | yes | 4999 | 21 | 2 | - | 4110 | 4310 | no | 903 B |
| 6x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x2 | confidential signer | min | yes | 1803 | 16 | 1 | - | 1156 | 1176 | yes |  |
| 8x2 | confidential signer | full | yes | 2358 | 26 | 3 | 8 | 1243 | 1221 | yes |  |
| 8x2 | confidential signer | full+spl | yes | 2726 | 33 | 3 | - | 1375 | 1225 | yes |  |
| 8x2 | confidential signer | full+data | yes | 2558 | 26 | 3 | - | 1443 | 1417 | yes |  |
| 8x2 | confidential signer | full+reply | yes | 2358 | 26 | 3 | - | 1243 | 1221 | yes |  |
| 8x2 | confidential signer | full+2tree | yes | 2396 | 27 | 3 | - | 1248 | 1225 | yes |  |
| 8x2 | confidential in-proof | min | yes | 1898 | 16 | 1 | - | 1252 | 1273 | yes |  |
| 8x2 | confidential in-proof | full | yes | 2357 | 25 | 2 | 8 | 1339 | 1318 | yes |  |
| 8x2 | confidential in-proof | full+spl | yes | 2725 | 32 | 2 | - | 1471 | 1322 | yes |  |
| 8x2 | confidential in-proof | full+data | yes | 2557 | 25 | 2 | - | 1539 | 1514 | yes |  |
| 8x2 | confidential in-proof | full+reply | yes | 2357 | 25 | 2 | - | 1339 | 1318 | yes |  |
| 8x2 | confidential in-proof | full+2tree | yes | 2395 | 26 | 2 | - | 1344 | 1322 | yes |  |
| 8x2 | anonymous hidden | min | yes | 1930 | 16 | 1 | - | 1284 | 1335 | yes |  |
| 8x2 | anonymous hidden | full | yes | 2357 | 22 | 2 | 8 | 1435 | 1454 | yes |  |
| 8x2 | anonymous hidden | full+spl | yes | 2725 | 29 | 2 | - | 1567 | 1458 | yes |  |
| 8x2 | anonymous hidden | full+data | yes | 2557 | 22 | 2 | - | 1635 | 1650 | yes |  |
| 8x2 | anonymous hidden | full+reply | yes | 2456 | 22 | 2 | - | 1534 | 1551 | yes |  |
| 8x2 | anonymous hidden | full+2tree | yes | 2395 | 23 | 2 | - | 1440 | 1458 | yes |  |
| 8x2 | anonymous public owners | min | yes | 1867 | 16 | 1 | - | 1220 | 1238 | yes |  |
| 8x2 | anonymous public owners | full | yes | 2486 | 26 | 3 | 8 | 1371 | 1357 | yes |  |
| 8x2 | anonymous public owners | full+spl | yes | 2854 | 33 | 3 | - | 1503 | 1361 | yes |  |
| 8x2 | anonymous public owners | full+data | yes | 2686 | 26 | 3 | - | 1571 | 1553 | yes |  |
| 8x2 | anonymous public owners | full+reply | yes | 2585 | 26 | 3 | - | 1470 | 1454 | yes |  |
| 8x2 | anonymous public owners | full+2tree | yes | 2524 | 27 | 3 | - | 1376 | 1361 | yes |  |
| 8x2 | confidential entry | min | yes | 3411 | 16 | 1 | - | 2764 | 2784 | yes |  |
| 8x2 | confidential entry | full | yes | 3966 | 26 | 3 | 2 | 2851 | 2829 | yes |  |
| 8x2 | confidential entry | full+spl | yes | 4334 | 33 | 3 | - | 2983 | 2833 | no | 238 B |
| 8x2 | confidential entry | full+data | yes | 4166 | 26 | 3 | - | 3051 | 3025 | no | 70 B |
| 8x2 | confidential entry | full+reply | yes | 3966 | 26 | 3 | - | 2851 | 2829 | yes |  |
| 8x2 | confidential entry | full+2tree | yes | 4004 | 27 | 3 | - | 2856 | 2833 | yes |  |
| 8x2 | anonymous entry | min | yes | 3570 | 16 | 1 | - | 2924 | 2943 | yes |  |
| 8x2 | anonymous entry | full | yes | 3997 | 22 | 2 | 1 | 3075 | 3062 | yes |  |
| 8x2 | anonymous entry | full+spl | yes | 4365 | 29 | 2 | - | 3207 | 3066 | no | 269 B |
| 8x2 | anonymous entry | full+data | yes | 4197 | 22 | 2 | - | 3275 | 3258 | no | 101 B |
| 8x2 | anonymous entry | full+reply | yes | 4096 | 22 | 2 | - | 3174 | 3159 | yes |  |
| 8x2 | anonymous entry | full+2tree | yes | 4035 | 23 | 2 | - | 3080 | 3066 | yes |  |
| 8x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x4 | confidential signer | min | yes | 2237 | 16 | 1 | - | 1590 | 1682 | yes |  |
| 8x4 | confidential signer | full | yes | 2792 | 26 | 3 | 8 | 1677 | 1727 | yes |  |
| 8x4 | confidential signer | full+spl | yes | 3160 | 33 | 3 | - | 1809 | 1731 | yes |  |
| 8x4 | confidential signer | full+data | yes | 3190 | 26 | 3 | - | 2075 | 2117 | yes |  |
| 8x4 | confidential signer | full+reply | yes | 2792 | 26 | 3 | - | 1677 | 1727 | yes |  |
| 8x4 | confidential signer | full+2tree | yes | 2830 | 27 | 3 | - | 1682 | 1731 | yes |  |
| 8x4 | confidential in-proof | min | yes | 2332 | 16 | 1 | - | 1686 | 1779 | yes |  |
| 8x4 | confidential in-proof | full | yes | 2791 | 25 | 2 | 8 | 1773 | 1824 | yes |  |
| 8x4 | confidential in-proof | full+spl | yes | 3159 | 32 | 2 | - | 1905 | 1828 | yes |  |
| 8x4 | confidential in-proof | full+data | yes | 3189 | 25 | 2 | - | 2171 | 2214 | yes |  |
| 8x4 | confidential in-proof | full+reply | yes | 2791 | 25 | 2 | - | 1773 | 1824 | yes |  |
| 8x4 | confidential in-proof | full+2tree | yes | 2829 | 26 | 2 | - | 1778 | 1828 | yes |  |
| 8x4 | anonymous hidden | min | yes | 2428 | 16 | 1 | - | 1782 | 1905 | yes |  |
| 8x4 | anonymous hidden | full | yes | 2855 | 22 | 2 | 8 | 1933 | 2024 | yes |  |
| 8x4 | anonymous hidden | full+spl | yes | 3223 | 29 | 2 | - | 2065 | 2028 | yes |  |
| 8x4 | anonymous hidden | full+data | yes | 3253 | 22 | 2 | - | 2331 | 2414 | yes |  |
| 8x4 | anonymous hidden | full+reply | yes | 3148 | 22 | 2 | - | 2226 | 2315 | yes |  |
| 8x4 | anonymous hidden | full+2tree | yes | 2893 | 23 | 2 | - | 1938 | 2028 | yes |  |
| 8x4 | anonymous public owners | min | yes | 2365 | 16 | 1 | - | 1718 | 1808 | yes |  |
| 8x4 | anonymous public owners | full | yes | 2984 | 26 | 3 | 8 | 1869 | 1927 | yes |  |
| 8x4 | anonymous public owners | full+spl | yes | 3352 | 33 | 3 | - | 2001 | 1931 | yes |  |
| 8x4 | anonymous public owners | full+data | yes | 3382 | 26 | 3 | - | 2267 | 2317 | yes |  |
| 8x4 | anonymous public owners | full+reply | yes | 3277 | 26 | 3 | - | 2162 | 2218 | yes |  |
| 8x4 | anonymous public owners | full+2tree | yes | 3022 | 27 | 3 | - | 1874 | 1931 | yes |  |
| 8x4 | confidential entry | min | yes | 3845 | 16 | 1 | - | 3198 | 3290 | yes |  |
| 8x4 | confidential entry | full | yes | 4400 | 26 | 3 | none | 3285 | 3335 | no | 304 B |
| 8x4 | confidential entry | full+spl | yes | 4768 | 33 | 3 | - | 3417 | 3339 | no | 672 B |
| 8x4 | confidential entry | full+data | yes | 4798 | 26 | 3 | - | 3683 | 3725 | no | 702 B |
| 8x4 | confidential entry | full+reply | yes | 4400 | 26 | 3 | - | 3285 | 3335 | no | 304 B |
| 8x4 | confidential entry | full+2tree | yes | 4438 | 27 | 3 | - | 3290 | 3339 | no | 342 B |
| 8x4 | anonymous entry | min | yes | 4068 | 16 | 1 | - | 3422 | 3513 | yes |  |
| 8x4 | anonymous entry | full | yes | 4495 | 22 | 2 | none | 3573 | 3632 | no | 399 B |
| 8x4 | anonymous entry | full+spl | yes | 4863 | 29 | 2 | - | 3705 | 3636 | no | 767 B |
| 8x4 | anonymous entry | full+data | yes | 4893 | 22 | 2 | - | 3971 | 4022 | no | 797 B |
| 8x4 | anonymous entry | full+reply | yes | 4788 | 22 | 2 | - | 3866 | 3923 | no | 692 B |
| 8x4 | anonymous entry | full+2tree | yes | 4533 | 23 | 2 | - | 3578 | 3636 | no | 437 B |
| 8x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x8 | confidential signer | min | yes | 3105 | 16 | 1 | - | 2458 | 2694 | yes |  |
| 8x8 | confidential signer | full | yes | 3660 | 26 | 3 | 5 | 2545 | 2739 | yes |  |
| 8x8 | confidential signer | full+spl | yes | 4028 | 33 | 3 | - | 2677 | 2743 | yes |  |
| 8x8 | confidential signer | full+data | yes | 4454 | 26 | 3 | - | 3339 | 3517 | no | 358 B |
| 8x8 | confidential signer | full+reply | yes | 3660 | 26 | 3 | - | 2545 | 2739 | yes |  |
| 8x8 | confidential signer | full+2tree | yes | 3698 | 27 | 3 | - | 2550 | 2743 | yes |  |
| 8x8 | confidential in-proof | min | yes | 3200 | 16 | 1 | - | 2554 | 2791 | yes |  |
| 8x8 | confidential in-proof | full | yes | 3659 | 25 | 2 | 4 | 2641 | 2836 | yes |  |
| 8x8 | confidential in-proof | full+spl | yes | 4027 | 32 | 2 | - | 2773 | 2840 | yes |  |
| 8x8 | confidential in-proof | full+data | yes | 4453 | 25 | 2 | - | 3435 | 3614 | no | 357 B |
| 8x8 | confidential in-proof | full+reply | yes | 3659 | 25 | 2 | - | 2641 | 2836 | yes |  |
| 8x8 | confidential in-proof | full+2tree | yes | 3697 | 26 | 2 | - | 2646 | 2840 | yes |  |
| 8x8 | anonymous hidden | min | yes | 3424 | 16 | 1 | - | 2778 | 3045 | yes |  |
| 8x8 | anonymous hidden | full | yes | 3851 | 22 | 2 | 2 | 2929 | 3164 | yes |  |
| 8x8 | anonymous hidden | full+spl | yes | 4219 | 29 | 2 | - | 3061 | 3168 | no | 123 B |
| 8x8 | anonymous hidden | full+data | yes | 4645 | 22 | 2 | - | 3723 | 3942 | no | 549 B |
| 8x8 | anonymous hidden | full+reply | yes | 4532 | 22 | 2 | - | 3610 | 3843 | no | 436 B |
| 8x8 | anonymous hidden | full+2tree | yes | 3889 | 23 | 2 | - | 2934 | 3168 | yes |  |
| 8x8 | anonymous public owners | min | yes | 3361 | 16 | 1 | - | 2714 | 2948 | yes |  |
| 8x8 | anonymous public owners | full | yes | 3980 | 26 | 3 | 2 | 2865 | 3067 | yes |  |
| 8x8 | anonymous public owners | full+spl | yes | 4348 | 33 | 3 | - | 2997 | 3071 | no | 252 B |
| 8x8 | anonymous public owners | full+data | yes | 4774 | 26 | 3 | - | 3659 | 3845 | no | 678 B |
| 8x8 | anonymous public owners | full+reply | yes | 4661 | 26 | 3 | - | 3546 | 3746 | no | 565 B |
| 8x8 | anonymous public owners | full+2tree | yes | 4018 | 27 | 3 | - | 2870 | 3071 | yes |  |
| 8x8 | confidential entry | min | yes | 4713 | 16 | 1 | - | 4066 | 4302 | no | 617 B |
| 8x8 | confidential entry | full | yes | 5268 | 26 | 3 | none | 4153 | 4347 | no | 1172 B |
| 8x8 | confidential entry | full+spl | yes | 5636 | 33 | 3 | - | 4285 | 4351 | no | 1540 B |
| 8x8 | confidential entry | full+data | yes | 6062 | 26 | 3 | - | 4947 | 5125 | no | 1966 B |
| 8x8 | confidential entry | full+reply | yes | 5268 | 26 | 3 | - | 4153 | 4347 | no | 1172 B |
| 8x8 | confidential entry | full+2tree | yes | 5306 | 27 | 3 | - | 4158 | 4351 | no | 1210 B |
| 8x8 | anonymous entry | min | yes | 5064 | 16 | 1 | - | 4418 | 4653 | no | 968 B |
| 8x8 | anonymous entry | full | yes | 5491 | 22 | 2 | none | 4569 | 4772 | no | 1395 B |
| 8x8 | anonymous entry | full+spl | yes | 5859 | 29 | 2 | - | 4701 | 4776 | no | 1763 B |
| 8x8 | anonymous entry | full+data | yes | 6285 | 22 | 2 | - | 5363 | 5550 | no | 2189 B |
| 8x8 | anonymous entry | full+reply | yes | 6172 | 22 | 2 | - | 5250 | 5451 | no | 2076 B |
| 8x8 | anonymous entry | full+2tree | yes | 5529 | 23 | 2 | - | 4574 | 4776 | no | 1433 B |
| 8x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x16 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x2 | confidential signer | min | yes | 2063 | 20 | 1 | - | 1284 | 1308 | yes |  |
| 12x2 | confidential signer | full | yes | 2618 | 30 | 3 | 10 | 1371 | 1353 | yes |  |
| 12x2 | confidential signer | full+spl | yes | 2986 | 37 | 3 | - | 1503 | 1357 | yes |  |
| 12x2 | confidential signer | full+data | yes | 2818 | 30 | 3 | - | 1571 | 1549 | yes |  |
| 12x2 | confidential signer | full+reply | yes | 2618 | 30 | 3 | - | 1371 | 1353 | yes |  |
| 12x2 | confidential signer | full+2tree | yes | 2657 | 31 | 3 | - | 1377 | 1357 | yes |  |
| 12x2 | confidential in-proof | min | yes | 2158 | 20 | 1 | - | 1380 | 1405 | yes |  |
| 12x2 | confidential in-proof | full | yes | 2617 | 29 | 2 | 10 | 1467 | 1450 | yes |  |
| 12x2 | confidential in-proof | full+spl | yes | 2985 | 36 | 2 | - | 1599 | 1454 | yes |  |
| 12x2 | confidential in-proof | full+data | yes | 2817 | 29 | 2 | - | 1667 | 1646 | yes |  |
| 12x2 | confidential in-proof | full+reply | yes | 2617 | 29 | 2 | - | 1467 | 1450 | yes |  |
| 12x2 | confidential in-proof | full+2tree | yes | 2656 | 30 | 2 | - | 1473 | 1454 | yes |  |
| 12x2 | anonymous hidden | min | yes | 2190 | 20 | 1 | - | 1412 | 1467 | yes |  |
| 12x2 | anonymous hidden | full | yes | 2617 | 26 | 2 | 10 | 1563 | 1586 | yes |  |
| 12x2 | anonymous hidden | full+spl | yes | 2985 | 33 | 2 | - | 1695 | 1590 | yes |  |
| 12x2 | anonymous hidden | full+data | yes | 2817 | 26 | 2 | - | 1763 | 1782 | yes |  |
| 12x2 | anonymous hidden | full+reply | yes | 2716 | 26 | 2 | - | 1662 | 1683 | yes |  |
| 12x2 | anonymous hidden | full+2tree | yes | 2656 | 27 | 2 | - | 1569 | 1590 | yes |  |
| 12x2 | anonymous public owners | min | yes | 2127 | 20 | 1 | - | 1348 | 1370 | yes |  |
| 12x2 | anonymous public owners | full | yes | 2746 | 30 | 3 | 10 | 1499 | 1489 | yes |  |
| 12x2 | anonymous public owners | full+spl | yes | 3114 | 37 | 3 | - | 1631 | 1493 | yes |  |
| 12x2 | anonymous public owners | full+data | yes | 2946 | 30 | 3 | - | 1699 | 1685 | yes |  |
| 12x2 | anonymous public owners | full+reply | yes | 2845 | 30 | 3 | - | 1598 | 1586 | yes |  |
| 12x2 | anonymous public owners | full+2tree | yes | 2785 | 31 | 3 | - | 1505 | 1493 | yes |  |
| 12x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x4 | confidential signer | min | yes | 2497 | 20 | 1 | - | 1718 | 1814 | yes |  |
| 12x4 | confidential signer | full | yes | 3052 | 30 | 3 | 10 | 1805 | 1859 | yes |  |
| 12x4 | confidential signer | full+spl | yes | 3420 | 37 | 3 | - | 1937 | 1863 | yes |  |
| 12x4 | confidential signer | full+data | yes | 3450 | 30 | 3 | - | 2203 | 2249 | yes |  |
| 12x4 | confidential signer | full+reply | yes | 3052 | 30 | 3 | - | 1805 | 1859 | yes |  |
| 12x4 | confidential signer | full+2tree | yes | 3091 | 31 | 3 | - | 1811 | 1863 | yes |  |
| 12x4 | confidential in-proof | min | yes | 2592 | 20 | 1 | - | 1814 | 1911 | yes |  |
| 12x4 | confidential in-proof | full | yes | 3051 | 29 | 2 | 10 | 1901 | 1956 | yes |  |
| 12x4 | confidential in-proof | full+spl | yes | 3419 | 36 | 2 | - | 2033 | 1960 | yes |  |
| 12x4 | confidential in-proof | full+data | yes | 3449 | 29 | 2 | - | 2299 | 2346 | yes |  |
| 12x4 | confidential in-proof | full+reply | yes | 3051 | 29 | 2 | - | 1901 | 1956 | yes |  |
| 12x4 | confidential in-proof | full+2tree | yes | 3090 | 30 | 2 | - | 1907 | 1960 | yes |  |
| 12x4 | anonymous hidden | min | yes | 2688 | 20 | 1 | - | 1910 | 2037 | yes |  |
| 12x4 | anonymous hidden | full | yes | 3115 | 26 | 2 | 10 | 2061 | 2156 | yes |  |
| 12x4 | anonymous hidden | full+spl | yes | 3483 | 33 | 2 | - | 2193 | 2160 | yes |  |
| 12x4 | anonymous hidden | full+data | yes | 3513 | 26 | 2 | - | 2459 | 2546 | yes |  |
| 12x4 | anonymous hidden | full+reply | yes | 3408 | 26 | 2 | - | 2354 | 2447 | yes |  |
| 12x4 | anonymous hidden | full+2tree | yes | 3154 | 27 | 2 | - | 2067 | 2160 | yes |  |
| 12x4 | anonymous public owners | min | yes | 2625 | 20 | 1 | - | 1846 | 1940 | yes |  |
| 12x4 | anonymous public owners | full | yes | 3244 | 30 | 3 | 9 | 1997 | 2059 | yes |  |
| 12x4 | anonymous public owners | full+spl | yes | 3612 | 37 | 3 | - | 2129 | 2063 | yes |  |
| 12x4 | anonymous public owners | full+data | yes | 3642 | 30 | 3 | - | 2395 | 2449 | yes |  |
| 12x4 | anonymous public owners | full+reply | yes | 3537 | 30 | 3 | - | 2290 | 2350 | yes |  |
| 12x4 | anonymous public owners | full+2tree | yes | 3283 | 31 | 3 | - | 2003 | 2063 | yes |  |
| 12x4 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x8 | confidential signer | min | yes | 3365 | 20 | 1 | - | 2586 | 2826 | yes |  |
| 12x8 | confidential signer | full | yes | 3920 | 30 | 3 | 2 | 2673 | 2871 | yes |  |
| 12x8 | confidential signer | full+spl | yes | 4288 | 37 | 3 | - | 2805 | 2875 | no | 192 B |
| 12x8 | confidential signer | full+data | yes | 4714 | 30 | 3 | - | 3467 | 3649 | no | 618 B |
| 12x8 | confidential signer | full+reply | yes | 3920 | 30 | 3 | - | 2673 | 2871 | yes |  |
| 12x8 | confidential signer | full+2tree | yes | 3959 | 31 | 3 | - | 2679 | 2875 | yes |  |
| 12x8 | confidential in-proof | min | yes | 3460 | 20 | 1 | - | 2682 | 2923 | yes |  |
| 12x8 | confidential in-proof | full | yes | 3919 | 29 | 2 | 1 | 2769 | 2968 | yes |  |
| 12x8 | confidential in-proof | full+spl | yes | 4287 | 36 | 2 | - | 2901 | 2972 | no | 191 B |
| 12x8 | confidential in-proof | full+data | yes | 4713 | 29 | 2 | - | 3563 | 3746 | no | 617 B |
| 12x8 | confidential in-proof | full+reply | yes | 3919 | 29 | 2 | - | 2769 | 2968 | yes |  |
| 12x8 | confidential in-proof | full+2tree | yes | 3958 | 30 | 2 | - | 2775 | 2972 | yes |  |
| 12x8 | anonymous hidden | min | yes | 3684 | 20 | 1 | - | 2906 | 3177 | yes |  |
| 12x8 | anonymous hidden | full | yes | 4111 | 26 | 2 | none | 3057 | 3296 | no | 15 B |
| 12x8 | anonymous hidden | full+spl | yes | 4479 | 33 | 2 | - | 3189 | 3300 | no | 383 B |
| 12x8 | anonymous hidden | full+data | yes | 4905 | 26 | 2 | - | 3851 | 4074 | no | 809 B |
| 12x8 | anonymous hidden | full+reply | yes | 4792 | 26 | 2 | - | 3738 | 3975 | no | 696 B |
| 12x8 | anonymous hidden | full+2tree | yes | 4150 | 27 | 2 | - | 3063 | 3300 | no | 54 B |
| 12x8 | anonymous public owners | min | yes | 3621 | 20 | 1 | - | 2842 | 3080 | yes |  |
| 12x8 | anonymous public owners | full | yes | 4240 | 30 | 3 | none | 2993 | 3199 | no | 144 B |
| 12x8 | anonymous public owners | full+spl | yes | 4608 | 37 | 3 | - | 3125 | 3203 | no | 512 B |
| 12x8 | anonymous public owners | full+data | yes | 5034 | 30 | 3 | - | 3787 | 3977 | no | 938 B |
| 12x8 | anonymous public owners | full+reply | yes | 4921 | 30 | 3 | - | 3674 | 3878 | no | 825 B |
| 12x8 | anonymous public owners | full+2tree | yes | 4279 | 31 | 3 | - | 2999 | 3203 | no | 183 B |
| 12x8 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x2 | confidential signer | min | yes | 2323 | 24 | 1 | - | 1412 | 1440 | yes |  |
| 16x2 | confidential signer | full | yes | 2878 | 34 | 3 | 10 | 1499 | 1485 | yes |  |
| 16x2 | confidential signer | full+spl | yes | 3246 | 41 | 3 | - | 1631 | 1489 | yes |  |
| 16x2 | confidential signer | full+data | yes | 3078 | 34 | 3 | - | 1699 | 1681 | yes |  |
| 16x2 | confidential signer | full+reply | yes | 2878 | 34 | 3 | - | 1499 | 1485 | yes |  |
| 16x2 | confidential signer | full+2tree | yes | 2917 | 35 | 3 | - | 1505 | 1489 | yes |  |
| 16x2 | confidential in-proof | min | yes | 2418 | 24 | 1 | - | 1508 | 1537 | yes |  |
| 16x2 | confidential in-proof | full | yes | 2877 | 33 | 2 | 10 | 1595 | 1582 | yes |  |
| 16x2 | confidential in-proof | full+spl | yes | 3245 | 40 | 2 | - | 1727 | 1586 | yes |  |
| 16x2 | confidential in-proof | full+data | yes | 3077 | 33 | 2 | - | 1795 | 1778 | yes |  |
| 16x2 | confidential in-proof | full+reply | yes | 2877 | 33 | 2 | - | 1595 | 1582 | yes |  |
| 16x2 | confidential in-proof | full+2tree | yes | 2916 | 34 | 2 | - | 1601 | 1586 | yes |  |
| 16x2 | anonymous hidden | min | yes | 2450 | 24 | 1 | - | 1540 | 1599 | yes |  |
| 16x2 | anonymous hidden | full | yes | 2877 | 30 | 2 | 10 | 1691 | 1718 | yes |  |
| 16x2 | anonymous hidden | full+spl | yes | 3245 | 37 | 2 | - | 1823 | 1722 | yes |  |
| 16x2 | anonymous hidden | full+data | yes | 3077 | 30 | 2 | - | 1891 | 1914 | yes |  |
| 16x2 | anonymous hidden | full+reply | yes | 2976 | 30 | 2 | - | 1790 | 1815 | yes |  |
| 16x2 | anonymous hidden | full+2tree | yes | 2916 | 31 | 2 | - | 1697 | 1722 | yes |  |
| 16x2 | anonymous public owners | min | yes | 2387 | 24 | 1 | - | 1476 | 1502 | yes |  |
| 16x2 | anonymous public owners | full | yes | 3006 | 34 | 3 | 10 | 1627 | 1621 | yes |  |
| 16x2 | anonymous public owners | full+spl | yes | 3374 | 41 | 3 | - | 1759 | 1625 | yes |  |
| 16x2 | anonymous public owners | full+data | yes | 3206 | 34 | 3 | - | 1827 | 1817 | yes |  |
| 16x2 | anonymous public owners | full+reply | yes | 3105 | 34 | 3 | - | 1726 | 1718 | yes |  |
| 16x2 | anonymous public owners | full+2tree | yes | 3045 | 35 | 3 | - | 1633 | 1625 | yes |  |
| 16x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x4 | confidential signer | min | yes | 2757 | 24 | 1 | - | 1846 | 1946 | yes |  |
| 16x4 | confidential signer | full | yes | 3312 | 34 | 3 | 9 | 1933 | 1991 | yes |  |
| 16x4 | confidential signer | full+spl | yes | 3680 | 41 | 3 | - | 2065 | 1995 | yes |  |
| 16x4 | confidential signer | full+data | yes | 3710 | 34 | 3 | - | 2331 | 2381 | yes |  |
| 16x4 | confidential signer | full+reply | yes | 3312 | 34 | 3 | - | 1933 | 1991 | yes |  |
| 16x4 | confidential signer | full+2tree | yes | 3351 | 35 | 3 | - | 1939 | 1995 | yes |  |
| 16x4 | confidential in-proof | min | yes | 2852 | 24 | 1 | - | 1942 | 2043 | yes |  |
| 16x4 | confidential in-proof | full | yes | 3311 | 33 | 2 | 8 | 2029 | 2088 | yes |  |
| 16x4 | confidential in-proof | full+spl | yes | 3679 | 40 | 2 | - | 2161 | 2092 | yes |  |
| 16x4 | confidential in-proof | full+data | yes | 3709 | 33 | 2 | - | 2427 | 2478 | yes |  |
| 16x4 | confidential in-proof | full+reply | yes | 3311 | 33 | 2 | - | 2029 | 2088 | yes |  |
| 16x4 | confidential in-proof | full+2tree | yes | 3350 | 34 | 2 | - | 2035 | 2092 | yes |  |
| 16x4 | anonymous hidden | min | yes | 2948 | 24 | 1 | - | 2038 | 2169 | yes |  |
| 16x4 | anonymous hidden | full | yes | 3375 | 30 | 2 | 7 | 2189 | 2288 | yes |  |
| 16x4 | anonymous hidden | full+spl | yes | 3743 | 37 | 2 | - | 2321 | 2292 | yes |  |
| 16x4 | anonymous hidden | full+data | yes | 3773 | 30 | 2 | - | 2587 | 2678 | yes |  |
| 16x4 | anonymous hidden | full+reply | yes | 3668 | 30 | 2 | - | 2482 | 2579 | yes |  |
| 16x4 | anonymous hidden | full+2tree | yes | 3414 | 31 | 2 | - | 2195 | 2292 | yes |  |
| 16x4 | anonymous public owners | min | yes | 2885 | 24 | 1 | - | 1974 | 2072 | yes |  |
| 16x4 | anonymous public owners | full | yes | 3504 | 34 | 3 | 7 | 2125 | 2191 | yes |  |
| 16x4 | anonymous public owners | full+spl | yes | 3872 | 41 | 3 | - | 2257 | 2195 | yes |  |
| 16x4 | anonymous public owners | full+data | yes | 3902 | 34 | 3 | - | 2523 | 2581 | yes |  |
| 16x4 | anonymous public owners | full+reply | yes | 3797 | 34 | 3 | - | 2418 | 2482 | yes |  |
| 16x4 | anonymous public owners | full+2tree | yes | 3543 | 35 | 3 | - | 2131 | 2195 | yes |  |
| 16x4 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x8 | confidential signer | min | yes | 3625 | 24 | 1 | - | 2714 | 2958 | yes |  |
| 16x8 | confidential signer | full | yes | 4180 | 34 | 3 | none | 2801 | 3003 | no | 84 B |
| 16x8 | confidential signer | full+spl | yes | 4548 | 41 | 3 | - | 2933 | 3007 | no | 452 B |
| 16x8 | confidential signer | full+data | yes | 4974 | 34 | 3 | - | 3595 | 3781 | no | 878 B |
| 16x8 | confidential signer | full+reply | yes | 4180 | 34 | 3 | - | 2801 | 3003 | no | 84 B |
| 16x8 | confidential signer | full+2tree | yes | 4219 | 35 | 3 | - | 2807 | 3007 | no | 123 B |
| 16x8 | confidential in-proof | min | yes | 3720 | 24 | 1 | - | 2810 | 3055 | yes |  |
| 16x8 | confidential in-proof | full | yes | 4179 | 33 | 2 | none | 2897 | 3100 | no | 83 B |
| 16x8 | confidential in-proof | full+spl | yes | 4547 | 40 | 2 | - | 3029 | 3104 | no | 451 B |
| 16x8 | confidential in-proof | full+data | yes | 4973 | 33 | 2 | - | 3691 | 3878 | no | 877 B |
| 16x8 | confidential in-proof | full+reply | yes | 4179 | 33 | 2 | - | 2897 | 3100 | no | 83 B |
| 16x8 | confidential in-proof | full+2tree | yes | 4218 | 34 | 2 | - | 2903 | 3104 | no | 122 B |
| 16x8 | anonymous hidden | min | yes | 3944 | 24 | 1 | - | 3034 | 3309 | yes |  |
| 16x8 | anonymous hidden | full | yes | 4371 | 30 | 2 | none | 3185 | 3428 | no | 275 B |
| 16x8 | anonymous hidden | full+spl | yes | 4739 | 37 | 2 | - | 3317 | 3432 | no | 643 B |
| 16x8 | anonymous hidden | full+data | yes | 5165 | 30 | 2 | - | 3979 | 4206 | no | 1069 B |
| 16x8 | anonymous hidden | full+reply | yes | 5052 | 30 | 2 | - | 3866 | 4107 | no | 956 B |
| 16x8 | anonymous hidden | full+2tree | yes | 4410 | 31 | 2 | - | 3191 | 3432 | no | 314 B |
| 16x8 | anonymous public owners | min | yes | 3881 | 24 | 1 | - | 2970 | 3212 | yes |  |
| 16x8 | anonymous public owners | full | yes | 4500 | 34 | 3 | none | 3121 | 3331 | no | 404 B |
| 16x8 | anonymous public owners | full+spl | yes | 4868 | 41 | 3 | - | 3253 | 3335 | no | 772 B |
| 16x8 | anonymous public owners | full+data | yes | 5294 | 34 | 3 | - | 3915 | 4109 | no | 1198 B |
| 16x8 | anonymous public owners | full+reply | yes | 5181 | 34 | 3 | - | 3802 | 4010 | no | 1085 B |
| 16x8 | anonymous public owners | full+2tree | yes | 4539 | 35 | 3 | - | 3127 | 3335 | no | 443 B |
| 16x8 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 24x2 | confidential signer | min | yes | 2843 | 32 | 1 | - | 1668 | 1704 | yes |  |
| 24x2 | confidential signer | full | yes | 3398 | 42 | 3 | 8 | 1755 | 1749 | yes |  |
| 24x2 | confidential signer | full+spl | yes | 3766 | 49 | 3 | - | 1887 | 1753 | yes |  |
| 24x2 | confidential signer | full+data | yes | 3598 | 42 | 3 | - | 1955 | 1945 | yes |  |
| 24x2 | confidential signer | full+reply | yes | 3398 | 42 | 3 | - | 1755 | 1749 | yes |  |
| 24x2 | confidential signer | full+2tree | yes | 3438 | 43 | 3 | - | 1762 | 1753 | yes |  |
| 24x2 | confidential in-proof | min | yes | 2938 | 32 | 1 | - | 1764 | 1801 | yes |  |
| 24x2 | confidential in-proof | full | yes | 3397 | 41 | 2 | 7 | 1851 | 1846 | yes |  |
| 24x2 | confidential in-proof | full+spl | yes | 3765 | 48 | 2 | - | 1983 | 1850 | yes |  |
| 24x2 | confidential in-proof | full+data | yes | 3597 | 41 | 2 | - | 2051 | 2042 | yes |  |
| 24x2 | confidential in-proof | full+reply | yes | 3397 | 41 | 2 | - | 1851 | 1846 | yes |  |
| 24x2 | confidential in-proof | full+2tree | yes | 3437 | 42 | 2 | - | 1858 | 1850 | yes |  |
| 24x2 | anonymous hidden | min | yes | 2970 | 32 | 1 | - | 1796 | 1863 | yes |  |
| 24x2 | anonymous hidden | full | yes | 3397 | 38 | 2 | 7 | 1947 | 1982 | yes |  |
| 24x2 | anonymous hidden | full+spl | yes | 3765 | 45 | 2 | - | 2079 | 1986 | yes |  |
| 24x2 | anonymous hidden | full+data | yes | 3597 | 38 | 2 | - | 2147 | 2178 | yes |  |
| 24x2 | anonymous hidden | full+reply | yes | 3496 | 38 | 2 | - | 2046 | 2079 | yes |  |
| 24x2 | anonymous hidden | full+2tree | yes | 3437 | 39 | 2 | - | 1954 | 1986 | yes |  |
| 24x2 | anonymous public owners | min | yes | 2907 | 32 | 1 | - | 1732 | 1766 | yes |  |
| 24x2 | anonymous public owners | full | yes | 3526 | 42 | 3 | 6 | 1883 | 1885 | yes |  |
| 24x2 | anonymous public owners | full+spl | yes | 3894 | 49 | 3 | - | 2015 | 1889 | yes |  |
| 24x2 | anonymous public owners | full+data | yes | 3726 | 42 | 3 | - | 2083 | 2081 | yes |  |
| 24x2 | anonymous public owners | full+reply | yes | 3625 | 42 | 3 | - | 1982 | 1982 | yes |  |
| 24x2 | anonymous public owners | full+2tree | yes | 3566 | 43 | 3 | - | 1890 | 1889 | yes |  |
| 24x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 24x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 24x4 | confidential signer | min | yes | 3277 | 32 | 1 | - | 2102 | 2210 | yes |  |
| 24x4 | confidential signer | full | yes | 3832 | 42 | 3 | 3 | 2189 | 2255 | yes |  |
| 24x4 | confidential signer | full+spl | yes | 4200 | 49 | 3 | - | 2321 | 2259 | no | 104 B |
| 24x4 | confidential signer | full+data | yes | 4230 | 42 | 3 | - | 2587 | 2645 | no | 134 B |
| 24x4 | confidential signer | full+reply | yes | 3832 | 42 | 3 | - | 2189 | 2255 | yes |  |
| 24x4 | confidential signer | full+2tree | yes | 3872 | 43 | 3 | - | 2196 | 2259 | yes |  |
| 24x4 | confidential in-proof | min | yes | 3372 | 32 | 1 | - | 2198 | 2307 | yes |  |
| 24x4 | confidential in-proof | full | yes | 3831 | 41 | 2 | 2 | 2285 | 2352 | yes |  |
| 24x4 | confidential in-proof | full+spl | yes | 4199 | 48 | 2 | - | 2417 | 2356 | no | 103 B |
| 24x4 | confidential in-proof | full+data | yes | 4229 | 41 | 2 | - | 2683 | 2742 | no | 133 B |
| 24x4 | confidential in-proof | full+reply | yes | 3831 | 41 | 2 | - | 2285 | 2352 | yes |  |
| 24x4 | confidential in-proof | full+2tree | yes | 3871 | 42 | 2 | - | 2292 | 2356 | yes |  |
| 24x4 | anonymous hidden | min | yes | 3468 | 32 | 1 | - | 2294 | 2433 | yes |  |
| 24x4 | anonymous hidden | full | yes | 3895 | 38 | 2 | 2 | 2445 | 2552 | yes |  |
| 24x4 | anonymous hidden | full+spl | yes | 4263 | 45 | 2 | - | 2577 | 2556 | no | 167 B |
| 24x4 | anonymous hidden | full+data | yes | 4293 | 38 | 2 | - | 2843 | 2942 | no | 197 B |
| 24x4 | anonymous hidden | full+reply | yes | 4188 | 38 | 2 | - | 2738 | 2843 | no | 92 B |
| 24x4 | anonymous hidden | full+2tree | yes | 3935 | 39 | 2 | - | 2452 | 2556 | yes |  |
| 24x4 | anonymous public owners | min | yes | 3405 | 32 | 1 | - | 2230 | 2336 | yes |  |
| 24x4 | anonymous public owners | full | yes | 4024 | 42 | 3 | 1 | 2381 | 2455 | yes |  |
| 24x4 | anonymous public owners | full+spl | yes | 4392 | 49 | 3 | - | 2513 | 2459 | no | 296 B |
| 24x4 | anonymous public owners | full+data | yes | 4422 | 42 | 3 | - | 2779 | 2845 | no | 326 B |
| 24x4 | anonymous public owners | full+reply | yes | 4317 | 42 | 3 | - | 2674 | 2746 | no | 221 B |
| 24x4 | anonymous public owners | full+2tree | yes | 4064 | 43 | 3 | - | 2388 | 2459 | yes |  |
| 24x4 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 24x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 32x2 | confidential signer | min | yes | 3363 | 40 | 1 | - | 1924 | 1968 | yes |  |
| 32x2 | confidential signer | full | yes | 3918 | 50 | 3 | 2 | 2011 | 2013 | yes |  |
| 32x2 | confidential signer | full+spl | yes | 4286 | 57 | 3 | - | 2143 | 2017 | no | 190 B |
| 32x2 | confidential signer | full+data | yes | 4118 | 50 | 3 | - | 2211 | 2209 | no | 22 B |
| 32x2 | confidential signer | full+reply | yes | 3918 | 50 | 3 | - | 2011 | 2013 | yes |  |
| 32x2 | confidential signer | full+2tree | yes | 3959 | 51 | 3 | - | 2019 | 2017 | yes |  |
| 32x2 | confidential in-proof | min | yes | 3458 | 40 | 1 | - | 2020 | 2065 | yes |  |
| 32x2 | confidential in-proof | full | yes | 3917 | 49 | 2 | 1 | 2107 | 2110 | yes |  |
| 32x2 | confidential in-proof | full+spl | yes | 4285 | 56 | 2 | - | 2239 | 2114 | no | 189 B |
| 32x2 | confidential in-proof | full+data | yes | 4117 | 49 | 2 | - | 2307 | 2306 | no | 21 B |
| 32x2 | confidential in-proof | full+reply | yes | 3917 | 49 | 2 | - | 2107 | 2110 | yes |  |
| 32x2 | confidential in-proof | full+2tree | yes | 3958 | 50 | 2 | - | 2115 | 2114 | yes |  |
| 32x2 | anonymous hidden | min | yes | 3490 | 40 | 1 | - | 2052 | 2127 | yes |  |
| 32x2 | anonymous hidden | full | yes | 3917 | 46 | 2 | 1 | 2203 | 2246 | yes |  |
| 32x2 | anonymous hidden | full+spl | yes | 4285 | 53 | 2 | - | 2335 | 2250 | no | 189 B |
| 32x2 | anonymous hidden | full+data | yes | 4117 | 46 | 2 | - | 2403 | 2442 | no | 21 B |
| 32x2 | anonymous hidden | full+reply | yes | 4016 | 46 | 2 | - | 2302 | 2343 | yes |  |
| 32x2 | anonymous hidden | full+2tree | yes | 3958 | 47 | 2 | - | 2211 | 2250 | yes |  |
| 32x2 | anonymous public owners | min | yes | 3427 | 40 | 1 | - | 1988 | 2030 | yes |  |
| 32x2 | anonymous public owners | full | yes | 4046 | 50 | 3 | 1 | 2139 | 2149 | yes |  |
| 32x2 | anonymous public owners | full+spl | yes | 4414 | 57 | 3 | - | 2271 | 2153 | no | 318 B |
| 32x2 | anonymous public owners | full+data | yes | 4246 | 50 | 3 | - | 2339 | 2345 | no | 150 B |
| 32x2 | anonymous public owners | full+reply | yes | 4145 | 50 | 3 | - | 2238 | 2246 | no | 49 B |
| 32x2 | anonymous public owners | full+2tree | yes | 4087 | 51 | 3 | - | 2147 | 2153 | yes |  |
| 32x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 32x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 40x2 | confidential signer | min | yes | 3883 | 48 | 1 | - | 2180 | 2232 | yes |  |
| 40x2 | confidential signer | full | yes | 4438 | 58 | 3 | none | 2267 | 2277 | no | 342 B |
| 40x2 | confidential signer | full+spl | yes | 4806 | 65 | 3 | - | 2399 | 2281 | no | 710 B, 1 accounts |
| 40x2 | confidential signer | full+data | yes | 4638 | 58 | 3 | - | 2467 | 2473 | no | 542 B |
| 40x2 | confidential signer | full+reply | yes | 4438 | 58 | 3 | - | 2267 | 2277 | no | 342 B |
| 40x2 | confidential signer | full+2tree | yes | 4480 | 59 | 3 | - | 2276 | 2281 | no | 384 B |
| 40x2 | confidential in-proof | min | yes | 3978 | 48 | 1 | - | 2276 | 2329 | yes |  |
| 40x2 | confidential in-proof | full | yes | 4437 | 57 | 2 | none | 2363 | 2374 | no | 341 B |
| 40x2 | confidential in-proof | full+spl | yes | 4805 | 64 | 2 | - | 2495 | 2378 | no | 709 B |
| 40x2 | confidential in-proof | full+data | yes | 4637 | 57 | 2 | - | 2563 | 2570 | no | 541 B |
| 40x2 | confidential in-proof | full+reply | yes | 4437 | 57 | 2 | - | 2363 | 2374 | no | 341 B |
| 40x2 | confidential in-proof | full+2tree | yes | 4479 | 58 | 2 | - | 2372 | 2378 | no | 383 B |
| 40x2 | anonymous hidden | min | yes | 4010 | 48 | 1 | - | 2308 | 2391 | yes |  |
| 40x2 | anonymous hidden | full | yes | 4437 | 54 | 2 | none | 2459 | 2510 | no | 341 B |
| 40x2 | anonymous hidden | full+spl | yes | 4805 | 61 | 2 | - | 2591 | 2514 | no | 709 B |
| 40x2 | anonymous hidden | full+data | yes | 4637 | 54 | 2 | - | 2659 | 2706 | no | 541 B |
| 40x2 | anonymous hidden | full+reply | yes | 4536 | 54 | 2 | - | 2558 | 2607 | no | 440 B |
| 40x2 | anonymous hidden | full+2tree | yes | 4479 | 55 | 2 | - | 2468 | 2514 | no | 383 B |
| 40x2 | anonymous public owners | min | yes | 3947 | 48 | 1 | - | 2244 | 2294 | yes |  |
| 40x2 | anonymous public owners | full | yes | 4566 | 58 | 3 | none | 2395 | 2413 | no | 470 B |
| 40x2 | anonymous public owners | full+spl | yes | 4934 | 65 | 3 | - | 2527 | 2417 | no | 838 B, 1 accounts |
| 40x2 | anonymous public owners | full+data | yes | 4766 | 58 | 3 | - | 2595 | 2609 | no | 670 B |
| 40x2 | anonymous public owners | full+reply | yes | 4665 | 58 | 3 | - | 2494 | 2510 | no | 569 B |
| 40x2 | anonymous public owners | full+2tree | yes | 4608 | 59 | 3 | - | 2404 | 2417 | no | 512 B |
| 40x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 40x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 48x2 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 48x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 49x2 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 49x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x1 | merge | ring | yes | 1640 | 16 | 1 | - | - | - | yes |  |
| 8x1 | merge | owner signed | yes | 1737 | 17 | 2 | - | - | - | yes |  |
| 24x1 | merge | ring | yes | 2680 | 32 | 1 | - | - | - | yes |  |
| 24x1 | merge | owner signed | yes | 2777 | 33 | 2 | - | - | - | yes |  |
| 52x1 | merge | ring | yes | 4500 | 60 | 1 | - | - | - | no | 404 B |
| 52x1 | merge | owner signed | yes | 4597 | 61 | 2 | - | - | - | no | 501 B |
| 0x1 | deposit | min | yes | 1014 | 9 | 1 | - | - | - | yes |  |
| 0x1 | deposit | full | yes | 1285 | 15 | 2 | - | - | - | yes |  |
| 0x2 | deposit | min | yes | 1392 | 9 | 1 | - | - | - | yes |  |
| 0x2 | deposit | full | yes | 1663 | 15 | 2 | - | - | - | yes |  |
| 0x4 | deposit | min | yes | 2148 | 9 | 1 | - | - | - | yes |  |
| 0x4 | deposit | full | yes | 2419 | 15 | 2 | - | - | - | yes |  |
| 0x8 | deposit | min | yes | 3660 | 9 | 1 | - | - | - | yes |  |
| 0x8 | deposit | full | yes | 3931 | 15 | 2 | - | - | - | yes |  |

Entry capacities at two outputs. Each row is the widest owner run one transaction clears at that leg count, rows = run + a hidden sender. A confidential leg names its own destination, a hidden sender's legs name one. over: what stops the next owner.
| shape | rail | load | legs | leg kind | owner run | rows | accounts | signatures | frame | SPP CPI | fits | over |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 12x2 | confidential entry | min | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | min | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | min | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | min | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | min | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | min | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | min | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | min | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | min | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | min | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | min | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | min | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | catalog key |

Maxima. Load max is full with data tails, every extension but the cache, two SPP input trees, replies on anonymous frames. Each row widens one axis from that load to the largest value one transaction clears. reply: the reply length. messages: empty application messages. message bytes: one application message. over: what refuses one more step. Heap is not measured here.
| shape | rail | axis | widest | frame | SPP CPI | bytes | accounts | signatures | over |
|---|---|---|---|---|---|---|---|---|---|
| 1x2 | confidential signer | messages | 54 | 3166 | 3090 | 4083 | 20 | 3 | 21 B |
| 1x2 | confidential signer | message bytes | 1815 | 3179 | 3103 | 4096 | 20 | 3 | 1 B |
| 1x2 | confidential in-proof | messages | 54 | 3262 | 3187 | 4082 | 19 | 2 | 20 B |
| 1x2 | confidential in-proof | message bytes | 1816 | 3276 | 3201 | 4096 | 19 | 2 | 1 B |
| 1x2 | anonymous hidden | reply | 1849 | 3372 | 3336 | 4096 | 16 | 2 | 1 B |
| 1x2 | anonymous hidden | messages | 51 | 3355 | 3318 | 4079 | 16 | 2 | 17 B |
| 1x2 | anonymous hidden | message bytes | 1717 | 3372 | 3335 | 4096 | 16 | 2 | 1 B |
| 1x2 | anonymous public owners | reply | 1720 | 3179 | 3110 | 4096 | 20 | 3 | 1 B |
| 1x2 | anonymous public owners | messages | 47 | 3155 | 3085 | 4072 | 20 | 3 | 10 B |
| 1x2 | anonymous public owners | message bytes | 1588 | 3179 | 3109 | 4096 | 20 | 3 | 1 B |
| 1x2 | confidential entry | messages | 48 | 3170 | 3094 | 4087 | 20 | 3 | 25 B |
| 1x2 | confidential entry | message bytes | 1607 | 3179 | 3103 | 4096 | 20 | 3 | 1 B |
| 1x2 | anonymous entry | reply | 1609 | 3372 | 3304 | 4096 | 16 | 2 | 1 B |
| 1x2 | anonymous entry | messages | 44 | 3357 | 3288 | 4081 | 16 | 2 | 19 B |
| 1x2 | anonymous entry | message bytes | 1477 | 3372 | 3303 | 4096 | 16 | 2 | 1 B |
| 1x4 | confidential signer | messages | 35 | 3152 | 3144 | 4069 | 20 | 3 | 7 B |
| 1x4 | confidential signer | message bytes | 1183 | 3179 | 3171 | 4096 | 20 | 3 | 1 B |
| 1x4 | confidential in-proof | messages | 35 | 3248 | 3241 | 4068 | 19 | 2 | 6 B |
| 1x4 | confidential in-proof | message bytes | 1184 | 3276 | 3269 | 4096 | 19 | 2 | 1 B |
| 1x4 | anonymous hidden | reply | 384 | 3371 | 3403 | 4095 | 16 | 2 | 2 B |
| 1x4 | anonymous hidden | messages | 25 | 3361 | 3392 | 4085 | 16 | 2 | 23 B |
| 1x4 | anonymous hidden | message bytes | 827 | 3372 | 3403 | 4096 | 16 | 2 | 1 B |
| 1x4 | anonymous public owners | reply | 341 | 3178 | 3177 | 4095 | 20 | 3 | 2 B |
| 1x4 | anonymous public owners | messages | 21 | 3161 | 3159 | 4078 | 20 | 3 | 16 B |
| 1x4 | anonymous public owners | message bytes | 698 | 3179 | 3177 | 4096 | 20 | 3 | 1 B |
| 1x4 | confidential entry | messages | 29 | 3156 | 3148 | 4073 | 20 | 3 | 11 B |
| 1x4 | confidential entry | message bytes | 975 | 3179 | 3171 | 4096 | 20 | 3 | 1 B |
| 1x4 | anonymous entry | reply | 304 | 3371 | 3371 | 4095 | 16 | 2 | 2 B |
| 1x4 | anonymous entry | messages | 18 | 3363 | 3362 | 4087 | 16 | 2 | 25 B |
| 1x4 | anonymous entry | message bytes | 587 | 3372 | 3371 | 4096 | 16 | 2 | 1 B |
| 1x8 | confidential signer | messages | none | - | - | - | - | - | 46 B |
| 1x8 | confidential signer | message bytes | none | - | - | - | - | - | 81 B |
| 1x8 | confidential in-proof | messages | none | - | - | - | - | - | 45 B |
| 1x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 80 B |
| 1x8 | anonymous hidden | reply | none | - | - | - | - | - | 918 B |
| 1x8 | anonymous hidden | messages | none | - | - | - | - | - | 918 B |
| 1x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 953 B |
| 1x8 | anonymous public owners | reply | none | - | - | - | - | - | 1047 B |
| 1x8 | anonymous public owners | messages | none | - | - | - | - | - | 1047 B |
| 1x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1082 B |
| 1x8 | confidential entry | messages | none | - | - | - | - | - | 254 B |
| 1x8 | confidential entry | message bytes | none | - | - | - | - | - | 289 B |
| 1x8 | anonymous entry | reply | none | - | - | - | - | - | 1158 B |
| 1x8 | anonymous entry | messages | none | - | - | - | - | - | 1158 B |
| 1x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1193 B |
| 2x2 | confidential signer | messages | 52 | 3130 | 3055 | 4080 | 21 | 3 | 18 B |
| 2x2 | confidential signer | message bytes | 1750 | 3146 | 3071 | 4096 | 21 | 3 | 1 B |
| 2x2 | confidential in-proof | messages | 52 | 3226 | 3152 | 4079 | 20 | 2 | 17 B |
| 2x2 | confidential in-proof | message bytes | 1751 | 3243 | 3169 | 4096 | 20 | 2 | 1 B |
| 2x2 | anonymous hidden | reply | 1784 | 3339 | 3304 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous hidden | messages | 49 | 3319 | 3283 | 4076 | 17 | 2 | 14 B |
| 2x2 | anonymous hidden | message bytes | 1652 | 3339 | 3303 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous public owners | reply | 1655 | 3146 | 3078 | 4096 | 21 | 3 | 1 B |
| 2x2 | anonymous public owners | messages | 45 | 3119 | 3050 | 4069 | 21 | 3 | 7 B |
| 2x2 | anonymous public owners | message bytes | 1523 | 3146 | 3077 | 4096 | 21 | 3 | 1 B |
| 2x2 | confidential entry | messages | 40 | 3130 | 3055 | 4080 | 21 | 3 | 18 B |
| 2x2 | confidential entry | message bytes | 1342 | 3146 | 3071 | 4096 | 21 | 3 | 1 B |
| 2x2 | anonymous entry | reply | 1344 | 3339 | 3272 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous entry | messages | 36 | 3317 | 3249 | 4074 | 17 | 2 | 12 B |
| 2x2 | anonymous entry | message bytes | 1212 | 3339 | 3271 | 4096 | 17 | 2 | 1 B |
| 2x2 | delegate | messages | 59 | 3312 | 3293 | 4066 | 17 | 2 | 4 B |
| 2x2 | delegate | message bytes | 2002 | 3342 | 3323 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous delegate | reply | 1907 | 3342 | 3330 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous delegate | messages | 53 | 3335 | 3322 | 4089 | 17 | 2 | 27 B |
| 2x2 | anonymous delegate | message bytes | 1775 | 3342 | 3329 | 4096 | 17 | 2 | 1 B |
| 2x4 | confidential signer | messages | 33 | 3116 | 3109 | 4066 | 21 | 3 | 4 B |
| 2x4 | confidential signer | message bytes | 1118 | 3146 | 3139 | 4096 | 21 | 3 | 1 B |
| 2x4 | confidential in-proof | messages | 33 | 3212 | 3206 | 4065 | 20 | 2 | 3 B |
| 2x4 | confidential in-proof | message bytes | 1119 | 3243 | 3237 | 4096 | 20 | 2 | 1 B |
| 2x4 | anonymous hidden | reply | 362 | 3337 | 3370 | 4094 | 17 | 2 | 1 B |
| 2x4 | anonymous hidden | messages | 23 | 3325 | 3357 | 4082 | 17 | 2 | 20 B |
| 2x4 | anonymous hidden | message bytes | 762 | 3339 | 3371 | 4096 | 17 | 2 | 1 B |
| 2x4 | anonymous public owners | reply | 319 | 3144 | 3144 | 4094 | 21 | 3 | 1 B |
| 2x4 | anonymous public owners | messages | 19 | 3125 | 3124 | 4075 | 21 | 3 | 13 B |
| 2x4 | anonymous public owners | message bytes | 633 | 3146 | 3145 | 4096 | 21 | 3 | 1 B |
| 2x4 | confidential entry | messages | 21 | 3116 | 3109 | 4066 | 21 | 3 | 4 B |
| 2x4 | confidential entry | message bytes | 710 | 3146 | 3139 | 4096 | 21 | 3 | 1 B |
| 2x4 | anonymous entry | reply | 216 | 3339 | 3340 | 4096 | 17 | 2 | 3 B |
| 2x4 | anonymous entry | messages | 10 | 3323 | 3323 | 4080 | 17 | 2 | 18 B |
| 2x4 | anonymous entry | message bytes | 322 | 3339 | 3339 | 4096 | 17 | 2 | 1 B |
| 2x8 | confidential signer | messages | none | - | - | - | - | - | 111 B |
| 2x8 | confidential signer | message bytes | none | - | - | - | - | - | 146 B |
| 2x8 | confidential in-proof | messages | none | - | - | - | - | - | 110 B |
| 2x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 145 B |
| 2x8 | anonymous hidden | reply | none | - | - | - | - | - | 983 B |
| 2x8 | anonymous hidden | messages | none | - | - | - | - | - | 983 B |
| 2x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1018 B |
| 2x8 | anonymous public owners | reply | none | - | - | - | - | - | 1112 B |
| 2x8 | anonymous public owners | messages | none | - | - | - | - | - | 1112 B |
| 2x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1147 B |
| 2x8 | confidential entry | messages | none | - | - | - | - | - | 519 B |
| 2x8 | confidential entry | message bytes | none | - | - | - | - | - | 554 B |
| 2x8 | anonymous entry | reply | none | - | - | - | - | - | 1423 B |
| 2x8 | anonymous entry | messages | none | - | - | - | - | - | 1423 B |
| 2x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1458 B |
| 3x2 | confidential signer | messages | 50 | 3094 | 3020 | 4077 | 22 | 3 | 15 B |
| 3x2 | confidential signer | message bytes | 1685 | 3113 | 3039 | 4096 | 22 | 3 | 1 B |
| 3x2 | confidential in-proof | messages | 50 | 3190 | 3117 | 4076 | 21 | 2 | 14 B |
| 3x2 | confidential in-proof | message bytes | 1686 | 3210 | 3137 | 4096 | 21 | 2 | 1 B |
| 3x2 | anonymous hidden | reply | 1719 | 3306 | 3272 | 4096 | 18 | 2 | 1 B |
| 3x2 | anonymous hidden | messages | 47 | 3283 | 3248 | 4073 | 18 | 2 | 11 B |
| 3x2 | anonymous hidden | message bytes | 1587 | 3306 | 3271 | 4096 | 18 | 2 | 1 B |
| 3x2 | anonymous public owners | reply | 1590 | 3113 | 3046 | 4096 | 22 | 3 | 1 B |
| 3x2 | anonymous public owners | messages | 43 | 3083 | 3015 | 4066 | 22 | 3 | 4 B |
| 3x2 | anonymous public owners | message bytes | 1458 | 3113 | 3045 | 4096 | 22 | 3 | 1 B |
| 3x2 | confidential entry | messages | 32 | 3090 | 3016 | 4073 | 22 | 3 | 11 B |
| 3x2 | confidential entry | message bytes | 1077 | 3113 | 3039 | 4096 | 22 | 3 | 1 B |
| 3x2 | anonymous entry | reply | 1079 | 3306 | 3240 | 4096 | 18 | 2 | 1 B |
| 3x2 | anonymous entry | messages | 28 | 3277 | 3210 | 4067 | 18 | 2 | 5 B |
| 3x2 | anonymous entry | message bytes | 947 | 3306 | 3239 | 4096 | 18 | 2 | 1 B |
| 3x4 | confidential signer | messages | 31 | 3080 | 3074 | 4063 | 22 | 3 | 1 B |
| 3x4 | confidential signer | message bytes | 1053 | 3113 | 3107 | 4096 | 22 | 3 | 1 B |
| 3x4 | confidential in-proof | messages | 32 | 3210 | 3205 | 4096 | 21 | 2 | 34 B |
| 3x4 | confidential in-proof | message bytes | 1054 | 3210 | 3205 | 4096 | 21 | 2 | 1 B |
| 3x4 | anonymous hidden | reply | 341 | 3306 | 3340 | 4096 | 18 | 2 | 3 B |
| 3x4 | anonymous hidden | messages | 21 | 3289 | 3322 | 4079 | 18 | 2 | 17 B |
| 3x4 | anonymous hidden | message bytes | 697 | 3306 | 3339 | 4096 | 18 | 2 | 1 B |
| 3x4 | anonymous public owners | reply | 298 | 3113 | 3114 | 4096 | 22 | 3 | 3 B |
| 3x4 | anonymous public owners | messages | 17 | 3089 | 3089 | 4072 | 22 | 3 | 10 B |
| 3x4 | anonymous public owners | message bytes | 568 | 3113 | 3113 | 4096 | 22 | 3 | 1 B |
| 3x4 | confidential entry | messages | 14 | 3110 | 3104 | 4093 | 22 | 3 | 31 B |
| 3x4 | confidential entry | message bytes | 445 | 3113 | 3107 | 4096 | 22 | 3 | 1 B |
| 3x4 | anonymous entry | reply | 127 | 3304 | 3306 | 4094 | 18 | 2 | 1 B |
| 3x4 | anonymous entry | messages | 2 | 3283 | 3284 | 4073 | 18 | 2 | 11 B |
| 3x4 | anonymous entry | message bytes | 57 | 3306 | 3307 | 4096 | 18 | 2 | 1 B |
| 3x8 | confidential signer | messages | none | - | - | - | - | - | 176 B |
| 3x8 | confidential signer | message bytes | none | - | - | - | - | - | 211 B |
| 3x8 | confidential in-proof | messages | none | - | - | - | - | - | 175 B |
| 3x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 210 B |
| 3x8 | anonymous hidden | reply | none | - | - | - | - | - | 1048 B |
| 3x8 | anonymous hidden | messages | none | - | - | - | - | - | 1048 B |
| 3x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1083 B |
| 3x8 | anonymous public owners | reply | none | - | - | - | - | - | 1177 B |
| 3x8 | anonymous public owners | messages | none | - | - | - | - | - | 1177 B |
| 3x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1212 B |
| 3x8 | confidential entry | messages | none | - | - | - | - | - | 784 B |
| 3x8 | confidential entry | message bytes | none | - | - | - | - | - | 819 B |
| 3x8 | anonymous entry | reply | none | - | - | - | - | - | 1688 B |
| 3x8 | anonymous entry | messages | none | - | - | - | - | - | 1688 B |
| 3x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1723 B |
| 4x2 | confidential signer | messages | 48 | 3058 | 2985 | 4074 | 23 | 3 | 12 B |
| 4x2 | confidential signer | message bytes | 1620 | 3080 | 3007 | 4096 | 23 | 3 | 1 B |
| 4x2 | confidential in-proof | messages | 48 | 3154 | 3082 | 4073 | 22 | 2 | 11 B |
| 4x2 | confidential in-proof | message bytes | 1621 | 3177 | 3105 | 4096 | 22 | 2 | 1 B |
| 4x2 | anonymous hidden | reply | 1654 | 3273 | 3240 | 4096 | 19 | 2 | 1 B |
| 4x2 | anonymous hidden | messages | 45 | 3247 | 3213 | 4070 | 19 | 2 | 8 B |
| 4x2 | anonymous hidden | message bytes | 1522 | 3273 | 3239 | 4096 | 19 | 2 | 1 B |
| 4x2 | anonymous public owners | reply | 1525 | 3080 | 3014 | 4096 | 23 | 3 | 1 B |
| 4x2 | anonymous public owners | messages | 41 | 3047 | 2980 | 4063 | 23 | 3 | 1 B |
| 4x2 | anonymous public owners | message bytes | 1393 | 3080 | 3013 | 4096 | 23 | 3 | 1 B |
| 4x2 | confidential entry | messages | 24 | 3050 | 2977 | 4066 | 23 | 3 | 4 B |
| 4x2 | confidential entry | message bytes | 812 | 3080 | 3007 | 4096 | 23 | 3 | 1 B |
| 4x2 | anonymous entry | reply | 814 | 3273 | 3208 | 4096 | 19 | 2 | 1 B |
| 4x2 | anonymous entry | messages | 21 | 3271 | 3205 | 4094 | 19 | 2 | 32 B |
| 4x2 | anonymous entry | message bytes | 682 | 3273 | 3207 | 4096 | 19 | 2 | 1 B |
| 4x4 | confidential signer | messages | 30 | 3078 | 3073 | 4094 | 23 | 3 | 32 B |
| 4x4 | confidential signer | message bytes | 988 | 3080 | 3075 | 4096 | 23 | 3 | 1 B |
| 4x4 | confidential in-proof | messages | 30 | 3174 | 3170 | 4093 | 22 | 2 | 31 B |
| 4x4 | confidential in-proof | message bytes | 989 | 3177 | 3173 | 4096 | 22 | 2 | 1 B |
| 4x4 | anonymous hidden | reply | 319 | 3272 | 3307 | 4095 | 19 | 2 | 2 B |
| 4x4 | anonymous hidden | messages | 19 | 3253 | 3287 | 4076 | 19 | 2 | 14 B |
| 4x4 | anonymous hidden | message bytes | 632 | 3273 | 3307 | 4096 | 19 | 2 | 1 B |
| 4x4 | anonymous public owners | reply | 276 | 3079 | 3081 | 4095 | 23 | 3 | 2 B |
| 4x4 | anonymous public owners | messages | 15 | 3053 | 3054 | 4069 | 23 | 3 | 7 B |
| 4x4 | anonymous public owners | message bytes | 503 | 3080 | 3081 | 4096 | 23 | 3 | 1 B |
| 4x4 | confidential entry | messages | 6 | 3070 | 3065 | 4086 | 23 | 3 | 24 B |
| 4x4 | confidential entry | message bytes | 180 | 3080 | 3075 | 4096 | 23 | 3 | 1 B |
| 4x4 | anonymous entry | reply | none | - | - | - | - | - | 173 B |
| 4x4 | anonymous entry | messages | none | - | - | - | - | - | 173 B |
| 4x4 | anonymous entry | message bytes | none | - | - | - | - | - | 208 B |
| 4x4 | delegate | messages | 37 | 3260 | 3311 | 4080 | 19 | 2 | 18 B |
| 4x4 | delegate | message bytes | 1240 | 3276 | 3327 | 4096 | 19 | 2 | 1 B |
| 4x4 | anonymous delegate | reply | 360 | 3275 | 3333 | 4095 | 19 | 2 | 2 B |
| 4x4 | anonymous delegate | messages | 23 | 3269 | 3326 | 4089 | 19 | 2 | 27 B |
| 4x4 | anonymous delegate | message bytes | 755 | 3276 | 3333 | 4096 | 19 | 2 | 1 B |
| 4x8 | confidential signer | messages | none | - | - | - | - | - | 241 B |
| 4x8 | confidential signer | message bytes | none | - | - | - | - | - | 276 B |
| 4x8 | confidential in-proof | messages | none | - | - | - | - | - | 240 B |
| 4x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 275 B |
| 4x8 | anonymous hidden | reply | none | - | - | - | - | - | 1113 B |
| 4x8 | anonymous hidden | messages | none | - | - | - | - | - | 1113 B |
| 4x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1148 B |
| 4x8 | anonymous public owners | reply | none | - | - | - | - | - | 1242 B |
| 4x8 | anonymous public owners | messages | none | - | - | - | - | - | 1242 B |
| 4x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1277 B |
| 4x8 | confidential entry | messages | none | - | - | - | - | - | 1049 B |
| 4x8 | confidential entry | message bytes | none | - | - | - | - | - | 1084 B |
| 4x8 | anonymous entry | reply | none | - | - | - | - | - | 1953 B |
| 4x8 | anonymous entry | messages | none | - | - | - | - | - | 1953 B |
| 4x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1988 B |
| 5x2 | confidential signer | messages | 46 | 3022 | 2950 | 4071 | 24 | 3 | 9 B |
| 5x2 | confidential signer | message bytes | 1555 | 3047 | 2975 | 4096 | 24 | 3 | 1 B |
| 5x2 | confidential in-proof | messages | 46 | 3118 | 3047 | 4070 | 23 | 2 | 8 B |
| 5x2 | confidential in-proof | message bytes | 1556 | 3144 | 3073 | 4096 | 23 | 2 | 1 B |
| 5x2 | anonymous hidden | reply | 1589 | 3240 | 3208 | 4096 | 20 | 2 | 1 B |
| 5x2 | anonymous hidden | messages | 43 | 3211 | 3178 | 4067 | 20 | 2 | 5 B |
| 5x2 | anonymous hidden | message bytes | 1457 | 3240 | 3207 | 4096 | 20 | 2 | 1 B |
| 5x2 | anonymous public owners | reply | 1460 | 3047 | 2982 | 4096 | 24 | 3 | 1 B |
| 5x2 | anonymous public owners | messages | 40 | 3045 | 2979 | 4094 | 24 | 3 | 32 B |
| 5x2 | anonymous public owners | message bytes | 1328 | 3047 | 2981 | 4096 | 24 | 3 | 1 B |
| 5x2 | confidential entry | messages | 17 | 3044 | 2972 | 4093 | 24 | 3 | 31 B |
| 5x2 | confidential entry | message bytes | 547 | 3047 | 2975 | 4096 | 24 | 3 | 1 B |
| 5x2 | anonymous entry | reply | 549 | 3240 | 3176 | 4096 | 20 | 2 | 1 B |
| 5x2 | anonymous entry | messages | 13 | 3231 | 3166 | 4087 | 20 | 2 | 25 B |
| 5x2 | anonymous entry | message bytes | 417 | 3240 | 3175 | 4096 | 20 | 2 | 1 B |
| 5x4 | confidential signer | messages | 28 | 3042 | 3038 | 4091 | 24 | 3 | 29 B |
| 5x4 | confidential signer | message bytes | 923 | 3047 | 3043 | 4096 | 24 | 3 | 1 B |
| 5x4 | confidential in-proof | messages | 28 | 3138 | 3135 | 4090 | 23 | 2 | 28 B |
| 5x4 | confidential in-proof | message bytes | 924 | 3144 | 3141 | 4096 | 23 | 2 | 1 B |
| 5x4 | anonymous hidden | reply | 297 | 3238 | 3274 | 4094 | 20 | 2 | 1 B |
| 5x4 | anonymous hidden | messages | 17 | 3217 | 3252 | 4073 | 20 | 2 | 11 B |
| 5x4 | anonymous hidden | message bytes | 567 | 3240 | 3275 | 4096 | 20 | 2 | 1 B |
| 5x4 | anonymous public owners | reply | 254 | 3045 | 3048 | 4094 | 24 | 3 | 1 B |
| 5x4 | anonymous public owners | messages | 13 | 3017 | 3019 | 4066 | 24 | 3 | 4 B |
| 5x4 | anonymous public owners | message bytes | 438 | 3047 | 3049 | 4096 | 24 | 3 | 1 B |
| 5x4 | confidential entry | messages | none | - | - | - | - | - | 50 B |
| 5x4 | confidential entry | message bytes | none | - | - | - | - | - | 85 B |
| 5x4 | anonymous entry | reply | none | - | - | - | - | - | 438 B |
| 5x4 | anonymous entry | messages | none | - | - | - | - | - | 438 B |
| 5x4 | anonymous entry | message bytes | none | - | - | - | - | - | 473 B |
| 5x8 | confidential signer | messages | none | - | - | - | - | - | 306 B |
| 5x8 | confidential signer | message bytes | none | - | - | - | - | - | 341 B |
| 5x8 | confidential in-proof | messages | none | - | - | - | - | - | 305 B |
| 5x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 340 B |
| 5x8 | anonymous hidden | reply | none | - | - | - | - | - | 1178 B |
| 5x8 | anonymous hidden | messages | none | - | - | - | - | - | 1178 B |
| 5x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1213 B |
| 5x8 | anonymous public owners | reply | none | - | - | - | - | - | 1307 B |
| 5x8 | anonymous public owners | messages | none | - | - | - | - | - | 1307 B |
| 5x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1342 B |
| 5x8 | confidential entry | messages | none | - | - | - | - | - | 1314 B |
| 5x8 | confidential entry | message bytes | none | - | - | - | - | - | 1349 B |
| 5x8 | anonymous entry | reply | none | - | - | - | - | - | 2218 B |
| 5x8 | anonymous entry | messages | none | - | - | - | - | - | 2218 B |
| 5x8 | anonymous entry | message bytes | none | - | - | - | - | - | 2253 B |
| 6x2 | confidential signer | messages | 44 | 2986 | 2915 | 4068 | 25 | 3 | 6 B |
| 6x2 | confidential signer | message bytes | 1490 | 3014 | 2943 | 4096 | 25 | 3 | 1 B |
| 6x2 | confidential in-proof | messages | 44 | 3082 | 3012 | 4067 | 24 | 2 | 5 B |
| 6x2 | confidential in-proof | message bytes | 1491 | 3111 | 3041 | 4096 | 24 | 2 | 1 B |
| 6x2 | anonymous hidden | reply | 1524 | 3207 | 3176 | 4096 | 21 | 2 | 1 B |
| 6x2 | anonymous hidden | messages | 41 | 3175 | 3143 | 4064 | 21 | 2 | 2 B |
| 6x2 | anonymous hidden | message bytes | 1392 | 3207 | 3175 | 4096 | 21 | 2 | 1 B |
| 6x2 | anonymous public owners | reply | 1395 | 3014 | 2950 | 4096 | 25 | 3 | 1 B |
| 6x2 | anonymous public owners | messages | 38 | 3009 | 2944 | 4091 | 25 | 3 | 29 B |
| 6x2 | anonymous public owners | message bytes | 1263 | 3014 | 2949 | 4096 | 25 | 3 | 1 B |
| 6x2 | confidential entry | messages | 9 | 3004 | 2933 | 4086 | 25 | 3 | 24 B |
| 6x2 | confidential entry | message bytes | 282 | 3014 | 2943 | 4096 | 25 | 3 | 1 B |
| 6x2 | anonymous entry | reply | 284 | 3207 | 3144 | 4096 | 21 | 2 | 1 B |
| 6x2 | anonymous entry | messages | 5 | 3191 | 3127 | 4080 | 21 | 2 | 18 B |
| 6x2 | anonymous entry | message bytes | 152 | 3207 | 3143 | 4096 | 21 | 2 | 1 B |
| 6x4 | confidential signer | messages | 26 | 3006 | 3003 | 4088 | 25 | 3 | 26 B |
| 6x4 | confidential signer | message bytes | 858 | 3014 | 3011 | 4096 | 25 | 3 | 1 B |
| 6x4 | confidential in-proof | messages | 26 | 3102 | 3100 | 4087 | 24 | 2 | 25 B |
| 6x4 | confidential in-proof | message bytes | 859 | 3111 | 3109 | 4096 | 24 | 2 | 1 B |
| 6x4 | anonymous hidden | reply | 276 | 3207 | 3244 | 4096 | 21 | 2 | 3 B |
| 6x4 | anonymous hidden | messages | 15 | 3181 | 3217 | 4070 | 21 | 2 | 8 B |
| 6x4 | anonymous hidden | message bytes | 502 | 3207 | 3243 | 4096 | 21 | 2 | 1 B |
| 6x4 | anonymous public owners | reply | 233 | 3014 | 3018 | 4096 | 25 | 3 | 3 B |
| 6x4 | anonymous public owners | messages | 11 | 2981 | 2984 | 4063 | 25 | 3 | 1 B |
| 6x4 | anonymous public owners | message bytes | 373 | 3014 | 3017 | 4096 | 25 | 3 | 1 B |
| 6x4 | confidential entry | messages | none | - | - | - | - | - | 315 B |
| 6x4 | confidential entry | message bytes | none | - | - | - | - | - | 350 B |
| 6x4 | anonymous entry | reply | none | - | - | - | - | - | 703 B |
| 6x4 | anonymous entry | messages | none | - | - | - | - | - | 703 B |
| 6x4 | anonymous entry | message bytes | none | - | - | - | - | - | 738 B |
| 6x8 | confidential signer | messages | none | - | - | - | - | - | 371 B |
| 6x8 | confidential signer | message bytes | none | - | - | - | - | - | 406 B |
| 6x8 | confidential in-proof | messages | none | - | - | - | - | - | 370 B |
| 6x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 405 B |
| 6x8 | anonymous hidden | reply | none | - | - | - | - | - | 1243 B |
| 6x8 | anonymous hidden | messages | none | - | - | - | - | - | 1243 B |
| 6x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1278 B |
| 6x8 | anonymous public owners | reply | none | - | - | - | - | - | 1372 B |
| 6x8 | anonymous public owners | messages | none | - | - | - | - | - | 1372 B |
| 6x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1407 B |
| 6x8 | confidential entry | messages | none | - | - | - | - | - | 1579 B |
| 6x8 | confidential entry | message bytes | none | - | - | - | - | - | 1614 B |
| 6x8 | anonymous entry | reply | none | - | - | - | - | - | 2483 B |
| 6x8 | anonymous entry | messages | none | - | - | - | - | - | 2483 B |
| 6x8 | anonymous entry | message bytes | none | - | - | - | - | - | 2518 B |
| 8x2 | confidential signer | messages | 41 | 2948 | 2879 | 4096 | 27 | 3 | 34 B |
| 8x2 | confidential signer | message bytes | 1360 | 2948 | 2879 | 4096 | 27 | 3 | 1 B |
| 8x2 | confidential in-proof | messages | 41 | 3044 | 2976 | 4095 | 26 | 2 | 33 B |
| 8x2 | confidential in-proof | message bytes | 1361 | 3045 | 2977 | 4096 | 26 | 2 | 1 B |
| 8x2 | anonymous hidden | reply | 1394 | 3141 | 3112 | 4096 | 23 | 2 | 1 B |
| 8x2 | anonymous hidden | messages | 38 | 3137 | 3107 | 4092 | 23 | 2 | 30 B |
| 8x2 | anonymous hidden | message bytes | 1262 | 3141 | 3111 | 4096 | 23 | 2 | 1 B |
| 8x2 | anonymous public owners | reply | 1265 | 2948 | 2886 | 4096 | 27 | 3 | 1 B |
| 8x2 | anonymous public owners | messages | 34 | 2937 | 2874 | 4085 | 27 | 3 | 23 B |
| 8x2 | anonymous public owners | message bytes | 1133 | 2948 | 2885 | 4096 | 27 | 3 | 1 B |
| 8x2 | confidential entry | messages | none | - | - | - | - | - | 213 B |
| 8x2 | confidential entry | message bytes | none | - | - | - | - | - | 248 B |
| 8x2 | anonymous entry | reply | none | - | - | - | - | - | 343 B |
| 8x2 | anonymous entry | messages | none | - | - | - | - | - | 343 B |
| 8x2 | anonymous entry | message bytes | none | - | - | - | - | - | 378 B |
| 8x4 | confidential signer | messages | 22 | 2934 | 2933 | 4082 | 27 | 3 | 20 B |
| 8x4 | confidential signer | message bytes | 728 | 2948 | 2947 | 4096 | 27 | 3 | 1 B |
| 8x4 | confidential in-proof | messages | 22 | 3030 | 3030 | 4081 | 26 | 2 | 19 B |
| 8x4 | confidential in-proof | message bytes | 729 | 3045 | 3045 | 4096 | 26 | 2 | 1 B |
| 8x4 | anonymous hidden | reply | 232 | 3139 | 3178 | 4094 | 23 | 2 | 1 B |
| 8x4 | anonymous hidden | messages | 11 | 3109 | 3147 | 4064 | 23 | 2 | 2 B |
| 8x4 | anonymous hidden | message bytes | 372 | 3141 | 3179 | 4096 | 23 | 2 | 1 B |
| 8x4 | anonymous public owners | reply | 189 | 2946 | 2952 | 4094 | 27 | 3 | 1 B |
| 8x4 | anonymous public owners | messages | 8 | 2943 | 2948 | 4091 | 27 | 3 | 29 B |
| 8x4 | anonymous public owners | message bytes | 243 | 2948 | 2953 | 4096 | 27 | 3 | 1 B |
| 8x4 | confidential entry | messages | none | - | - | - | - | - | 845 B |
| 8x4 | confidential entry | message bytes | none | - | - | - | - | - | 880 B |
| 8x4 | anonymous entry | reply | none | - | - | - | - | - | 1233 B |
| 8x4 | anonymous entry | messages | none | - | - | - | - | - | 1233 B |
| 8x4 | anonymous entry | message bytes | none | - | - | - | - | - | 1268 B |
| 8x8 | confidential signer | messages | none | - | - | - | - | - | 501 B |
| 8x8 | confidential signer | message bytes | none | - | - | - | - | - | 536 B |
| 8x8 | confidential in-proof | messages | none | - | - | - | - | - | 500 B |
| 8x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 535 B |
| 8x8 | anonymous hidden | reply | none | - | - | - | - | - | 1373 B |
| 8x8 | anonymous hidden | messages | none | - | - | - | - | - | 1373 B |
| 8x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1408 B |
| 8x8 | anonymous public owners | reply | none | - | - | - | - | - | 1502 B |
| 8x8 | anonymous public owners | messages | none | - | - | - | - | - | 1502 B |
| 8x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1537 B |
| 8x8 | confidential entry | messages | none | - | - | - | - | - | 2109 B |
| 8x8 | confidential entry | message bytes | none | - | - | - | - | - | 2144 B |
| 8x8 | anonymous entry | reply | none | - | - | - | - | - | 3013 B |
| 8x8 | anonymous entry | messages | none | - | - | - | - | - | 3013 B |
| 8x8 | anonymous entry | message bytes | none | - | - | - | - | - | 3048 B |
| 12x2 | confidential signer | messages | 33 | 2805 | 2739 | 4085 | 31 | 3 | 23 B |
| 12x2 | confidential signer | message bytes | 1099 | 2816 | 2750 | 4096 | 31 | 3 | 1 B |
| 12x2 | confidential in-proof | messages | 33 | 2901 | 2836 | 4084 | 30 | 2 | 22 B |
| 12x2 | confidential in-proof | message bytes | 1100 | 2913 | 2848 | 4096 | 30 | 2 | 1 B |
| 12x2 | anonymous hidden | reply | 1133 | 3009 | 2983 | 4096 | 27 | 2 | 1 B |
| 12x2 | anonymous hidden | messages | 30 | 2994 | 2967 | 4081 | 27 | 2 | 19 B |
| 12x2 | anonymous hidden | message bytes | 1001 | 3009 | 2982 | 4096 | 27 | 2 | 1 B |
| 12x2 | anonymous public owners | reply | 1004 | 2816 | 2757 | 4096 | 31 | 3 | 1 B |
| 12x2 | anonymous public owners | messages | 26 | 2794 | 2734 | 4074 | 31 | 3 | 12 B |
| 12x2 | anonymous public owners | message bytes | 872 | 2816 | 2756 | 4096 | 31 | 3 | 1 B |
| 12x4 | confidential signer | messages | 14 | 2791 | 2793 | 4071 | 31 | 3 | 9 B |
| 12x4 | confidential signer | message bytes | 467 | 2816 | 2818 | 4096 | 31 | 3 | 1 B |
| 12x4 | confidential in-proof | messages | 14 | 2887 | 2890 | 4070 | 30 | 2 | 8 B |
| 12x4 | confidential in-proof | message bytes | 468 | 2913 | 2916 | 4096 | 30 | 2 | 1 B |
| 12x4 | anonymous hidden | reply | 145 | 3007 | 3049 | 4094 | 27 | 2 | 1 B |
| 12x4 | anonymous hidden | messages | 4 | 3000 | 3041 | 4087 | 27 | 2 | 25 B |
| 12x4 | anonymous hidden | message bytes | 111 | 3009 | 3050 | 4096 | 27 | 2 | 1 B |
| 12x4 | anonymous public owners | reply | 102 | 2814 | 2823 | 4094 | 31 | 3 | 1 B |
| 12x4 | anonymous public owners | messages | 0 | 2799 | 2808 | 4079 | 31 | 3 | 18 B |
| 12x4 | anonymous public owners | message bytes | none | - | - | - | - | - | 18 B |
| 12x8 | confidential signer | messages | none | - | - | - | - | - | 762 B |
| 12x8 | confidential signer | message bytes | none | - | - | - | - | - | 797 B |
| 12x8 | confidential in-proof | messages | none | - | - | - | - | - | 761 B |
| 12x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 796 B |
| 12x8 | anonymous hidden | reply | none | - | - | - | - | - | 1634 B |
| 12x8 | anonymous hidden | messages | none | - | - | - | - | - | 1634 B |
| 12x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1669 B |
| 12x8 | anonymous public owners | reply | none | - | - | - | - | - | 1763 B |
| 12x8 | anonymous public owners | messages | none | - | - | - | - | - | 1763 B |
| 12x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1798 B |
| 16x2 | confidential signer | messages | 25 | 2661 | 2599 | 4073 | 35 | 3 | 11 B |
| 16x2 | confidential signer | message bytes | 839 | 2684 | 2622 | 4096 | 35 | 3 | 1 B |
| 16x2 | confidential in-proof | messages | 25 | 2757 | 2696 | 4072 | 34 | 2 | 10 B |
| 16x2 | confidential in-proof | message bytes | 840 | 2781 | 2720 | 4096 | 34 | 2 | 1 B |
| 16x2 | anonymous hidden | reply | 873 | 2877 | 2855 | 4096 | 31 | 2 | 1 B |
| 16x2 | anonymous hidden | messages | 22 | 2850 | 2827 | 4069 | 31 | 2 | 7 B |
| 16x2 | anonymous hidden | message bytes | 741 | 2877 | 2854 | 4096 | 31 | 2 | 1 B |
| 16x2 | anonymous public owners | reply | 744 | 2684 | 2629 | 4096 | 35 | 3 | 1 B |
| 16x2 | anonymous public owners | messages | 19 | 2684 | 2628 | 4096 | 35 | 3 | 34 B |
| 16x2 | anonymous public owners | message bytes | 612 | 2684 | 2628 | 4096 | 35 | 3 | 1 B |
| 16x4 | confidential signer | messages | 7 | 2681 | 2687 | 4093 | 35 | 3 | 31 B |
| 16x4 | confidential signer | message bytes | 207 | 2684 | 2690 | 4096 | 35 | 3 | 1 B |
| 16x4 | confidential in-proof | messages | 7 | 2777 | 2784 | 4092 | 34 | 2 | 30 B |
| 16x4 | confidential in-proof | message bytes | 208 | 2781 | 2788 | 4096 | 34 | 2 | 1 B |
| 16x4 | anonymous hidden | reply | none | - | - | - | - | - | 114 B |
| 16x4 | anonymous hidden | messages | none | - | - | - | - | - | 114 B |
| 16x4 | anonymous hidden | message bytes | none | - | - | - | - | - | 149 B |
| 16x4 | anonymous public owners | reply | none | - | - | - | - | - | 243 B |
| 16x4 | anonymous public owners | messages | none | - | - | - | - | - | 243 B |
| 16x4 | anonymous public owners | message bytes | none | - | - | - | - | - | 278 B |
| 16x8 | confidential signer | messages | none | - | - | - | - | - | 1022 B |
| 16x8 | confidential signer | message bytes | none | - | - | - | - | - | 1057 B |
| 16x8 | confidential in-proof | messages | none | - | - | - | - | - | 1021 B |
| 16x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 1056 B |
| 16x8 | anonymous hidden | reply | none | - | - | - | - | - | 1894 B |
| 16x8 | anonymous hidden | messages | none | - | - | - | - | - | 1894 B |
| 16x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1929 B |
| 16x8 | anonymous public owners | reply | none | - | - | - | - | - | 2023 B |
| 16x8 | anonymous public owners | messages | none | - | - | - | - | - | 2023 B |
| 16x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 2058 B |
| 24x2 | confidential signer | messages | 10 | 2408 | 2353 | 4084 | 43 | 3 | 22 B |
| 24x2 | confidential signer | message bytes | 318 | 2420 | 2365 | 4096 | 43 | 3 | 1 B |
| 24x2 | confidential in-proof | messages | 10 | 2504 | 2450 | 4083 | 42 | 2 | 21 B |
| 24x2 | confidential in-proof | message bytes | 319 | 2517 | 2463 | 4096 | 42 | 2 | 1 B |
| 24x2 | anonymous hidden | reply | 352 | 2613 | 2598 | 4096 | 39 | 2 | 1 B |
| 24x2 | anonymous hidden | messages | 7 | 2597 | 2581 | 4080 | 39 | 2 | 18 B |
| 24x2 | anonymous hidden | message bytes | 220 | 2613 | 2597 | 4096 | 39 | 2 | 1 B |
| 24x2 | anonymous public owners | reply | 223 | 2420 | 2372 | 4096 | 43 | 3 | 1 B |
| 24x2 | anonymous public owners | messages | 3 | 2397 | 2348 | 4073 | 43 | 3 | 11 B |
| 24x2 | anonymous public owners | message bytes | 91 | 2420 | 2371 | 4096 | 43 | 3 | 1 B |
| 24x4 | confidential signer | messages | none | - | - | - | - | - | 279 B |
| 24x4 | confidential signer | message bytes | none | - | - | - | - | - | 314 B |
| 24x4 | confidential in-proof | messages | none | - | - | - | - | - | 278 B |
| 24x4 | confidential in-proof | message bytes | none | - | - | - | - | - | 313 B |
| 24x4 | anonymous hidden | reply | none | - | - | - | - | - | 635 B |
| 24x4 | anonymous hidden | messages | none | - | - | - | - | - | 635 B |
| 24x4 | anonymous hidden | message bytes | none | - | - | - | - | - | 670 B |
| 24x4 | anonymous public owners | reply | none | - | - | - | - | - | 764 B |
| 24x4 | anonymous public owners | messages | none | - | - | - | - | - | 764 B |
| 24x4 | anonymous public owners | message bytes | none | - | - | - | - | - | 799 B |
| 32x2 | confidential signer | messages | none | - | - | - | - | - | 168 B |
| 32x2 | confidential signer | message bytes | none | - | - | - | - | - | 203 B |
| 32x2 | confidential in-proof | messages | none | - | - | - | - | - | 167 B |
| 32x2 | confidential in-proof | message bytes | none | - | - | - | - | - | 202 B |
| 32x2 | anonymous hidden | reply | none | - | - | - | - | - | 266 B |
| 32x2 | anonymous hidden | messages | none | - | - | - | - | - | 266 B |
| 32x2 | anonymous hidden | message bytes | none | - | - | - | - | - | 301 B |
| 32x2 | anonymous public owners | reply | none | - | - | - | - | - | 395 B |
| 32x2 | anonymous public owners | messages | none | - | - | - | - | - | 395 B |
| 32x2 | anonymous public owners | message bytes | none | - | - | - | - | - | 430 B |
| 40x2 | confidential signer | messages | none | - | - | - | - | - | 689 B |
| 40x2 | confidential signer | message bytes | none | - | - | - | - | - | 724 B |
| 40x2 | confidential in-proof | messages | none | - | - | - | - | - | 688 B |
| 40x2 | confidential in-proof | message bytes | none | - | - | - | - | - | 723 B |
| 40x2 | anonymous hidden | reply | none | - | - | - | - | - | 787 B |
| 40x2 | anonymous hidden | messages | none | - | - | - | - | - | 787 B |
| 40x2 | anonymous hidden | message bytes | none | - | - | - | - | - | 822 B |
| 40x2 | anonymous public owners | reply | none | - | - | - | - | - | 916 B |
| 40x2 | anonymous public owners | messages | none | - | - | - | - | - | 916 B |
| 40x2 | anonymous public owners | message bytes | none | - | - | - | - | - | 951 B |
