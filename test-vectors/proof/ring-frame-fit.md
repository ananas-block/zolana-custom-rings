Measured with the frame encoders, SPP's account builders and the v1 compiler. Ceilings 4096 B, 64 accounts, 12 signatures.
min: tracking root, no co-signer, no leg, no fee, the payer an owner where it may be. full: own, curator and tracking roots, one co-signer, 4 SOL legs, a fee, an outside payer, a body on every slot and one exit. The inline owner run is the inline ceilings' bound under full, the key's rows bound it apart. A shape's every input and output slot is published.
fits: the path that clears the transaction and CPI ceilings, the catalog key apart. limit: what stops a row with no path, rail for a shape the rail has no SPP key for, else the excess in accounts, signatures, bytes, buffer create or CPI data at that row's load. A missing catalog key is a choice of the catalog, no runtime limit.
| shape | rail | load | catalog key | inline bytes | inline accounts | signatures | inline owner run | inline over | frame | SPP CPI | buffered bytes | buffered accounts | fits | limit |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1x2 | confidential signer | min | yes | 1340 | 9 | 1 | - |  | 924 | 937 | 483 | 10 | inline |  |
| 1x2 | confidential signer | full | yes | 1895 | 19 | 3 | 1 |  | 1011 | 982 | 951 | 20 | inline |  |
| 1x2 | confidential signer | full+spl | yes | 2263 | 26 | 3 | - |  | 1143 | 986 | 1187 | 27 | inline |  |
| 1x2 | confidential signer | full+data | yes | 2095 | 19 | 3 | - |  | 1211 | 1178 | 951 | 20 | inline |  |
| 1x2 | confidential signer | full+reply | yes | 1895 | 19 | 3 | - |  | 1011 | 982 | 951 | 20 | inline |  |
| 1x2 | confidential signer | full+2tree | yes | 1933 | 20 | 3 | - |  | 1016 | 986 | 984 | 21 | inline |  |
| 1x2 | confidential in-proof | min | yes | 1435 | 9 | 1 | - |  | 1020 | 1034 | 482 | 10 | inline |  |
| 1x2 | confidential in-proof | full | yes | 1894 | 18 | 2 | 1 |  | 1107 | 1079 | 854 | 19 | inline |  |
| 1x2 | confidential in-proof | full+spl | yes | 2262 | 25 | 2 | - |  | 1239 | 1083 | 1090 | 26 | inline |  |
| 1x2 | confidential in-proof | full+data | yes | 2094 | 18 | 2 | - |  | 1307 | 1275 | 854 | 19 | inline |  |
| 1x2 | confidential in-proof | full+reply | yes | 1894 | 18 | 2 | - |  | 1107 | 1079 | 854 | 19 | inline |  |
| 1x2 | confidential in-proof | full+2tree | yes | 1932 | 19 | 2 | - |  | 1112 | 1083 | 887 | 20 | inline |  |
| 1x2 | anonymous hidden | min | yes | 1507 | 9 | 1 | - |  | 1092 | 1136 | 482 | 10 | inline |  |
| 1x2 | anonymous hidden | full | yes | 1942 | 15 | 2 | 1 |  | 1251 | 1263 | 758 | 16 | inline |  |
| 1x2 | anonymous hidden | full+spl | yes | 2310 | 22 | 2 | - |  | 1383 | 1267 | 994 | 23 | inline |  |
| 1x2 | anonymous hidden | full+data | yes | 2142 | 15 | 2 | - |  | 1451 | 1459 | 758 | 16 | inline |  |
| 1x2 | anonymous hidden | full+reply | yes | 2041 | 15 | 2 | - |  | 1350 | 1360 | 758 | 16 | inline |  |
| 1x2 | anonymous hidden | full+2tree | yes | 1980 | 16 | 2 | - |  | 1256 | 1267 | 791 | 17 | inline |  |
| 1x2 | anonymous public owners | min | yes | 1444 | 9 | 1 | - |  | 1028 | 1039 | 483 | 10 | inline |  |
| 1x2 | anonymous public owners | full | yes | 2071 | 19 | 3 | 1 |  | 1187 | 1166 | 951 | 20 | inline |  |
| 1x2 | anonymous public owners | full+spl | yes | 2439 | 26 | 3 | - |  | 1319 | 1170 | 1187 | 27 | inline |  |
| 1x2 | anonymous public owners | full+data | yes | 2271 | 19 | 3 | - |  | 1387 | 1362 | 951 | 20 | inline |  |
| 1x2 | anonymous public owners | full+reply | yes | 2170 | 19 | 3 | - |  | 1286 | 1263 | 951 | 20 | inline |  |
| 1x2 | anonymous public owners | full+2tree | yes | 2109 | 20 | 3 | - |  | 1192 | 1170 | 984 | 21 | inline |  |
| 1x2 | confidential entry | min | yes | 1548 | 9 | 1 | - |  | 1132 | 1145 | 483 | 10 | inline |  |
| 1x2 | confidential entry | full | yes | 2103 | 19 | 3 | 1 |  | 1219 | 1190 | 951 | 20 | inline |  |
| 1x2 | confidential entry | full+spl | yes | 2471 | 26 | 3 | - |  | 1351 | 1194 | 1187 | 27 | inline |  |
| 1x2 | confidential entry | full+data | yes | 2303 | 19 | 3 | - |  | 1419 | 1386 | 951 | 20 | inline |  |
| 1x2 | confidential entry | full+reply | yes | 2103 | 19 | 3 | - |  | 1219 | 1190 | 951 | 20 | inline |  |
| 1x2 | confidential entry | full+2tree | yes | 2141 | 20 | 3 | - |  | 1224 | 1194 | 984 | 21 | inline |  |
| 1x2 | anonymous entry | min | yes | 1747 | 9 | 1 | - |  | 1332 | 1344 | 482 | 10 | inline |  |
| 1x2 | anonymous entry | full | yes | 2182 | 15 | 2 | 1 |  | 1491 | 1471 | 758 | 16 | inline |  |
| 1x2 | anonymous entry | full+spl | yes | 2550 | 22 | 2 | - |  | 1623 | 1475 | 994 | 23 | inline |  |
| 1x2 | anonymous entry | full+data | yes | 2382 | 15 | 2 | - |  | 1691 | 1667 | 758 | 16 | inline |  |
| 1x2 | anonymous entry | full+reply | yes | 2281 | 15 | 2 | - |  | 1590 | 1568 | 758 | 16 | inline |  |
| 1x2 | anonymous entry | full+2tree | yes | 2220 | 16 | 2 | - |  | 1496 | 1475 | 791 | 17 | inline |  |
| 1x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x4 | confidential signer | min | yes | 1774 | 9 | 1 | - |  | 1358 | 1443 | 483 | 10 | inline |  |
| 1x4 | confidential signer | full | yes | 2329 | 19 | 3 | 1 |  | 1445 | 1488 | 951 | 20 | inline |  |
| 1x4 | confidential signer | full+spl | yes | 2697 | 26 | 3 | - |  | 1577 | 1492 | 1187 | 27 | inline |  |
| 1x4 | confidential signer | full+data | yes | 2727 | 19 | 3 | - |  | 1843 | 1878 | 951 | 20 | inline |  |
| 1x4 | confidential signer | full+reply | yes | 2329 | 19 | 3 | - |  | 1445 | 1488 | 951 | 20 | inline |  |
| 1x4 | confidential signer | full+2tree | yes | 2367 | 20 | 3 | - |  | 1450 | 1492 | 984 | 21 | inline |  |
| 1x4 | confidential in-proof | min | yes | 1869 | 9 | 1 | - |  | 1454 | 1540 | 482 | 10 | inline |  |
| 1x4 | confidential in-proof | full | yes | 2328 | 18 | 2 | 1 |  | 1541 | 1585 | 854 | 19 | inline |  |
| 1x4 | confidential in-proof | full+spl | yes | 2696 | 25 | 2 | - |  | 1673 | 1589 | 1090 | 26 | inline |  |
| 1x4 | confidential in-proof | full+data | yes | 2726 | 18 | 2 | - |  | 1939 | 1975 | 854 | 19 | inline |  |
| 1x4 | confidential in-proof | full+reply | yes | 2328 | 18 | 2 | - |  | 1541 | 1585 | 854 | 19 | inline |  |
| 1x4 | confidential in-proof | full+2tree | yes | 2366 | 19 | 2 | - |  | 1546 | 1589 | 887 | 20 | inline |  |
| 1x4 | anonymous hidden | min | yes | 2005 | 9 | 1 | - |  | 1590 | 1706 | 482 | 10 | inline |  |
| 1x4 | anonymous hidden | full | yes | 2440 | 15 | 2 | 1 |  | 1749 | 1833 | 758 | 16 | inline |  |
| 1x4 | anonymous hidden | full+spl | yes | 2808 | 22 | 2 | - |  | 1881 | 1837 | 994 | 23 | inline |  |
| 1x4 | anonymous hidden | full+data | yes | 2838 | 15 | 2 | - |  | 2147 | 2223 | 758 | 16 | inline |  |
| 1x4 | anonymous hidden | full+reply | yes | 2733 | 15 | 2 | - |  | 2042 | 2124 | 758 | 16 | inline |  |
| 1x4 | anonymous hidden | full+2tree | yes | 2478 | 16 | 2 | - |  | 1754 | 1837 | 791 | 17 | inline |  |
| 1x4 | anonymous public owners | min | yes | 1942 | 9 | 1 | - |  | 1526 | 1609 | 483 | 10 | inline |  |
| 1x4 | anonymous public owners | full | yes | 2569 | 19 | 3 | 1 |  | 1685 | 1736 | 951 | 20 | inline |  |
| 1x4 | anonymous public owners | full+spl | yes | 2937 | 26 | 3 | - |  | 1817 | 1740 | 1187 | 27 | inline |  |
| 1x4 | anonymous public owners | full+data | yes | 2967 | 19 | 3 | - |  | 2083 | 2126 | 951 | 20 | inline |  |
| 1x4 | anonymous public owners | full+reply | yes | 2862 | 19 | 3 | - |  | 1978 | 2027 | 951 | 20 | inline |  |
| 1x4 | anonymous public owners | full+2tree | yes | 2607 | 20 | 3 | - |  | 1690 | 1740 | 984 | 21 | inline |  |
| 1x4 | confidential entry | min | yes | 1982 | 9 | 1 | - |  | 1566 | 1651 | 483 | 10 | inline |  |
| 1x4 | confidential entry | full | yes | 2537 | 19 | 3 | 1 |  | 1653 | 1696 | 951 | 20 | inline |  |
| 1x4 | confidential entry | full+spl | yes | 2905 | 26 | 3 | - |  | 1785 | 1700 | 1187 | 27 | inline |  |
| 1x4 | confidential entry | full+data | yes | 2935 | 19 | 3 | - |  | 2051 | 2086 | 951 | 20 | inline |  |
| 1x4 | confidential entry | full+reply | yes | 2537 | 19 | 3 | - |  | 1653 | 1696 | 951 | 20 | inline |  |
| 1x4 | confidential entry | full+2tree | yes | 2575 | 20 | 3 | - |  | 1658 | 1700 | 984 | 21 | inline |  |
| 1x4 | anonymous entry | min | yes | 2245 | 9 | 1 | - |  | 1830 | 1914 | 482 | 10 | inline |  |
| 1x4 | anonymous entry | full | yes | 2680 | 15 | 2 | 1 |  | 1989 | 2041 | 758 | 16 | inline |  |
| 1x4 | anonymous entry | full+spl | yes | 3048 | 22 | 2 | - |  | 2121 | 2045 | 994 | 23 | inline |  |
| 1x4 | anonymous entry | full+data | yes | 3078 | 15 | 2 | - |  | 2387 | 2431 | 758 | 16 | inline |  |
| 1x4 | anonymous entry | full+reply | yes | 2973 | 15 | 2 | - |  | 2282 | 2332 | 758 | 16 | inline |  |
| 1x4 | anonymous entry | full+2tree | yes | 2718 | 16 | 2 | - |  | 1994 | 2045 | 791 | 17 | inline |  |
| 1x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x8 | confidential signer | min | yes | 2642 | 9 | 1 | - |  | 2226 | 2455 | 483 | 10 | inline |  |
| 1x8 | confidential signer | full | yes | 3197 | 19 | 3 | 1 |  | 2313 | 2500 | 951 | 20 | inline |  |
| 1x8 | confidential signer | full+spl | yes | 3565 | 26 | 3 | - |  | 2445 | 2504 | 1187 | 27 | inline |  |
| 1x8 | confidential signer | full+data | yes | 3991 | 19 | 3 | - |  | 3107 | 3278 | 951 | 20 | inline |  |
| 1x8 | confidential signer | full+reply | yes | 3197 | 19 | 3 | - |  | 2313 | 2500 | 951 | 20 | inline |  |
| 1x8 | confidential signer | full+2tree | yes | 3235 | 20 | 3 | - |  | 2318 | 2504 | 984 | 21 | inline |  |
| 1x8 | confidential in-proof | min | yes | 2737 | 9 | 1 | - |  | 2322 | 2552 | 482 | 10 | inline |  |
| 1x8 | confidential in-proof | full | yes | 3196 | 18 | 2 | 1 |  | 2409 | 2597 | 854 | 19 | inline |  |
| 1x8 | confidential in-proof | full+spl | yes | 3564 | 25 | 2 | - |  | 2541 | 2601 | 1090 | 26 | inline |  |
| 1x8 | confidential in-proof | full+data | yes | 3990 | 18 | 2 | - |  | 3203 | 3375 | 854 | 19 | inline |  |
| 1x8 | confidential in-proof | full+reply | yes | 3196 | 18 | 2 | - |  | 2409 | 2597 | 854 | 19 | inline |  |
| 1x8 | confidential in-proof | full+2tree | yes | 3234 | 19 | 2 | - |  | 2414 | 2601 | 887 | 20 | inline |  |
| 1x8 | anonymous hidden | min | yes | 3001 | 9 | 1 | - |  | 2586 | 2846 | 482 | 10 | inline |  |
| 1x8 | anonymous hidden | full | yes | 3436 | 15 | 2 | 1 |  | 2745 | 2973 | 758 | 16 | inline |  |
| 1x8 | anonymous hidden | full+spl | yes | 3804 | 22 | 2 | - |  | 2877 | 2977 | 994 | 23 | inline |  |
| 1x8 | anonymous hidden | full+data | yes | 4230 | 15 | 2 | - | 134 B | 3539 | 3751 | 758 | 16 | buffered |  |
| 1x8 | anonymous hidden | full+reply | yes | 4117 | 15 | 2 | - | 21 B | 3426 | 3652 | 758 | 16 | buffered |  |
| 1x8 | anonymous hidden | full+2tree | yes | 3474 | 16 | 2 | - |  | 2750 | 2977 | 791 | 17 | inline |  |
| 1x8 | anonymous public owners | min | yes | 2938 | 9 | 1 | - |  | 2522 | 2749 | 483 | 10 | inline |  |
| 1x8 | anonymous public owners | full | yes | 3565 | 19 | 3 | 1 |  | 2681 | 2876 | 951 | 20 | inline |  |
| 1x8 | anonymous public owners | full+spl | yes | 3933 | 26 | 3 | - |  | 2813 | 2880 | 1187 | 27 | inline |  |
| 1x8 | anonymous public owners | full+data | yes | 4359 | 19 | 3 | - | 263 B | 3475 | 3654 | 951 | 20 | buffered |  |
| 1x8 | anonymous public owners | full+reply | yes | 4246 | 19 | 3 | - | 150 B | 3362 | 3555 | 951 | 20 | buffered |  |
| 1x8 | anonymous public owners | full+2tree | yes | 3603 | 20 | 3 | - |  | 2686 | 2880 | 984 | 21 | inline |  |
| 1x8 | confidential entry | min | yes | 2850 | 9 | 1 | - |  | 2434 | 2663 | 483 | 10 | inline |  |
| 1x8 | confidential entry | full | yes | 3405 | 19 | 3 | 1 |  | 2521 | 2708 | 951 | 20 | inline |  |
| 1x8 | confidential entry | full+spl | yes | 3773 | 26 | 3 | - |  | 2653 | 2712 | 1187 | 27 | inline |  |
| 1x8 | confidential entry | full+data | yes | 4199 | 19 | 3 | - | 103 B | 3315 | 3486 | 951 | 20 | buffered |  |
| 1x8 | confidential entry | full+reply | yes | 3405 | 19 | 3 | - |  | 2521 | 2708 | 951 | 20 | inline |  |
| 1x8 | confidential entry | full+2tree | yes | 3443 | 20 | 3 | - |  | 2526 | 2712 | 984 | 21 | inline |  |
| 1x8 | anonymous entry | min | yes | 3241 | 9 | 1 | - |  | 2826 | 3054 | 482 | 10 | inline |  |
| 1x8 | anonymous entry | full | yes | 3676 | 15 | 2 | 1 |  | 2985 | 3181 | 758 | 16 | inline |  |
| 1x8 | anonymous entry | full+spl | yes | 4044 | 22 | 2 | - |  | 3117 | 3185 | 994 | 23 | inline |  |
| 1x8 | anonymous entry | full+data | yes | 4470 | 15 | 2 | - | 374 B | 3779 | 3959 | 758 | 16 | buffered |  |
| 1x8 | anonymous entry | full+reply | yes | 4357 | 15 | 2 | - | 261 B | 3666 | 3860 | 758 | 16 | buffered |  |
| 1x8 | anonymous entry | full+2tree | yes | 3714 | 16 | 2 | - |  | 2990 | 3185 | 791 | 17 | inline |  |
| 1x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 2x2 | confidential signer | min | yes | 1405 | 10 | 1 | - |  | 956 | 970 | 516 | 11 | inline |  |
| 2x2 | confidential signer | full | yes | 1960 | 20 | 3 | 2 |  | 1043 | 1015 | 984 | 21 | inline |  |
| 2x2 | confidential signer | full+spl | yes | 2328 | 27 | 3 | - |  | 1175 | 1019 | 1220 | 28 | inline |  |
| 2x2 | confidential signer | full+data | yes | 2160 | 20 | 3 | - |  | 1243 | 1211 | 984 | 21 | inline |  |
| 2x2 | confidential signer | full+reply | yes | 1960 | 20 | 3 | - |  | 1043 | 1015 | 984 | 21 | inline |  |
| 2x2 | confidential signer | full+2tree | yes | 1998 | 21 | 3 | - |  | 1048 | 1019 | 1017 | 22 | inline |  |
| 2x2 | confidential in-proof | min | yes | 1500 | 10 | 1 | - |  | 1052 | 1067 | 515 | 11 | inline |  |
| 2x2 | confidential in-proof | full | yes | 1959 | 19 | 2 | 2 |  | 1139 | 1112 | 887 | 20 | inline |  |
| 2x2 | confidential in-proof | full+spl | yes | 2327 | 26 | 2 | - |  | 1271 | 1116 | 1123 | 27 | inline |  |
| 2x2 | confidential in-proof | full+data | yes | 2159 | 19 | 2 | - |  | 1339 | 1308 | 887 | 20 | inline |  |
| 2x2 | confidential in-proof | full+reply | yes | 1959 | 19 | 2 | - |  | 1139 | 1112 | 887 | 20 | inline |  |
| 2x2 | confidential in-proof | full+2tree | yes | 1997 | 20 | 2 | - |  | 1144 | 1116 | 920 | 21 | inline |  |
| 2x2 | anonymous hidden | min | yes | 1572 | 10 | 1 | - |  | 1124 | 1169 | 515 | 11 | inline |  |
| 2x2 | anonymous hidden | full | yes | 2007 | 16 | 2 | 2 |  | 1283 | 1296 | 791 | 17 | inline |  |
| 2x2 | anonymous hidden | full+spl | yes | 2375 | 23 | 2 | - |  | 1415 | 1300 | 1027 | 24 | inline |  |
| 2x2 | anonymous hidden | full+data | yes | 2207 | 16 | 2 | - |  | 1483 | 1492 | 791 | 17 | inline |  |
| 2x2 | anonymous hidden | full+reply | yes | 2106 | 16 | 2 | - |  | 1382 | 1393 | 791 | 17 | inline |  |
| 2x2 | anonymous hidden | full+2tree | yes | 2045 | 17 | 2 | - |  | 1288 | 1300 | 824 | 18 | inline |  |
| 2x2 | anonymous public owners | min | yes | 1509 | 10 | 1 | - |  | 1060 | 1072 | 516 | 11 | inline |  |
| 2x2 | anonymous public owners | full | yes | 2136 | 20 | 3 | 2 |  | 1219 | 1199 | 984 | 21 | inline |  |
| 2x2 | anonymous public owners | full+spl | yes | 2504 | 27 | 3 | - |  | 1351 | 1203 | 1220 | 28 | inline |  |
| 2x2 | anonymous public owners | full+data | yes | 2336 | 20 | 3 | - |  | 1419 | 1395 | 984 | 21 | inline |  |
| 2x2 | anonymous public owners | full+reply | yes | 2235 | 20 | 3 | - |  | 1318 | 1296 | 984 | 21 | inline |  |
| 2x2 | anonymous public owners | full+2tree | yes | 2174 | 21 | 3 | - |  | 1224 | 1203 | 1017 | 22 | inline |  |
| 2x2 | confidential entry | min | yes | 1813 | 10 | 1 | - |  | 1364 | 1378 | 516 | 11 | inline |  |
| 2x2 | confidential entry | full | yes | 2368 | 20 | 3 | 2 |  | 1451 | 1423 | 984 | 21 | inline |  |
| 2x2 | confidential entry | full+spl | yes | 2736 | 27 | 3 | - |  | 1583 | 1427 | 1220 | 28 | inline |  |
| 2x2 | confidential entry | full+data | yes | 2568 | 20 | 3 | - |  | 1651 | 1619 | 984 | 21 | inline |  |
| 2x2 | confidential entry | full+reply | yes | 2368 | 20 | 3 | - |  | 1451 | 1423 | 984 | 21 | inline |  |
| 2x2 | confidential entry | full+2tree | yes | 2406 | 21 | 3 | - |  | 1456 | 1427 | 1017 | 22 | inline |  |
| 2x2 | anonymous entry | min | yes | 2012 | 10 | 1 | - |  | 1564 | 1577 | 515 | 11 | inline |  |
| 2x2 | anonymous entry | full | yes | 2447 | 16 | 2 | 2 |  | 1723 | 1704 | 791 | 17 | inline |  |
| 2x2 | anonymous entry | full+spl | yes | 2815 | 23 | 2 | - |  | 1855 | 1708 | 1027 | 24 | inline |  |
| 2x2 | anonymous entry | full+data | yes | 2647 | 16 | 2 | - |  | 1923 | 1900 | 791 | 17 | inline |  |
| 2x2 | anonymous entry | full+reply | yes | 2546 | 16 | 2 | - |  | 1822 | 1801 | 791 | 17 | inline |  |
| 2x2 | anonymous entry | full+2tree | yes | 2485 | 17 | 2 | - |  | 1728 | 1708 | 824 | 18 | inline |  |
| 2x2 | delegate | min | yes | 1405 | 10 | 1 | - |  | 956 | 970 | 516 | 11 | inline |  |
| 2x2 | delegate | full | yes | 1748 | 16 | 2 | - |  | 1027 | 1015 | 788 | 17 | inline |  |
| 2x2 | delegate | full+spl | yes | 1988 | 23 | 2 | - |  | 1031 | 1019 | 1024 | 24 | inline |  |
| 2x2 | delegate | full+data | yes | 1948 | 16 | 2 | - |  | 1227 | 1211 | 788 | 17 | inline |  |
| 2x2 | delegate | full+reply | yes | 1748 | 16 | 2 | - |  | 1027 | 1015 | 788 | 17 | inline |  |
| 2x2 | delegate | full+2tree | yes | 1786 | 17 | 2 | - |  | 1032 | 1019 | 821 | 18 | inline |  |
| 2x2 | anonymous delegate | min | yes | 1509 | 10 | 1 | - |  | 1060 | 1072 | 516 | 11 | inline |  |
| 2x2 | anonymous delegate | full | yes | 1924 | 16 | 2 | - |  | 1203 | 1199 | 788 | 17 | inline |  |
| 2x2 | anonymous delegate | full+spl | yes | 2164 | 23 | 2 | - |  | 1207 | 1203 | 1024 | 24 | inline |  |
| 2x2 | anonymous delegate | full+data | yes | 2124 | 16 | 2 | - |  | 1403 | 1395 | 788 | 17 | inline |  |
| 2x2 | anonymous delegate | full+reply | yes | 2023 | 16 | 2 | - |  | 1302 | 1296 | 788 | 17 | inline |  |
| 2x2 | anonymous delegate | full+2tree | yes | 1962 | 17 | 2 | - |  | 1208 | 1203 | 821 | 18 | inline |  |
| 2x4 | confidential signer | min | yes | 1839 | 10 | 1 | - |  | 1390 | 1476 | 516 | 11 | inline |  |
| 2x4 | confidential signer | full | yes | 2394 | 20 | 3 | 2 |  | 1477 | 1521 | 984 | 21 | inline |  |
| 2x4 | confidential signer | full+spl | yes | 2762 | 27 | 3 | - |  | 1609 | 1525 | 1220 | 28 | inline |  |
| 2x4 | confidential signer | full+data | yes | 2792 | 20 | 3 | - |  | 1875 | 1911 | 984 | 21 | inline |  |
| 2x4 | confidential signer | full+reply | yes | 2394 | 20 | 3 | - |  | 1477 | 1521 | 984 | 21 | inline |  |
| 2x4 | confidential signer | full+2tree | yes | 2432 | 21 | 3 | - |  | 1482 | 1525 | 1017 | 22 | inline |  |
| 2x4 | confidential in-proof | min | yes | 1934 | 10 | 1 | - |  | 1486 | 1573 | 515 | 11 | inline |  |
| 2x4 | confidential in-proof | full | yes | 2393 | 19 | 2 | 2 |  | 1573 | 1618 | 887 | 20 | inline |  |
| 2x4 | confidential in-proof | full+spl | yes | 2761 | 26 | 2 | - |  | 1705 | 1622 | 1123 | 27 | inline |  |
| 2x4 | confidential in-proof | full+data | yes | 2791 | 19 | 2 | - |  | 1971 | 2008 | 887 | 20 | inline |  |
| 2x4 | confidential in-proof | full+reply | yes | 2393 | 19 | 2 | - |  | 1573 | 1618 | 887 | 20 | inline |  |
| 2x4 | confidential in-proof | full+2tree | yes | 2431 | 20 | 2 | - |  | 1578 | 1622 | 920 | 21 | inline |  |
| 2x4 | anonymous hidden | min | yes | 2070 | 10 | 1 | - |  | 1622 | 1739 | 515 | 11 | inline |  |
| 2x4 | anonymous hidden | full | yes | 2505 | 16 | 2 | 2 |  | 1781 | 1866 | 791 | 17 | inline |  |
| 2x4 | anonymous hidden | full+spl | yes | 2873 | 23 | 2 | - |  | 1913 | 1870 | 1027 | 24 | inline |  |
| 2x4 | anonymous hidden | full+data | yes | 2903 | 16 | 2 | - |  | 2179 | 2256 | 791 | 17 | inline |  |
| 2x4 | anonymous hidden | full+reply | yes | 2798 | 16 | 2 | - |  | 2074 | 2157 | 791 | 17 | inline |  |
| 2x4 | anonymous hidden | full+2tree | yes | 2543 | 17 | 2 | - |  | 1786 | 1870 | 824 | 18 | inline |  |
| 2x4 | anonymous public owners | min | yes | 2007 | 10 | 1 | - |  | 1558 | 1642 | 516 | 11 | inline |  |
| 2x4 | anonymous public owners | full | yes | 2634 | 20 | 3 | 2 |  | 1717 | 1769 | 984 | 21 | inline |  |
| 2x4 | anonymous public owners | full+spl | yes | 3002 | 27 | 3 | - |  | 1849 | 1773 | 1220 | 28 | inline |  |
| 2x4 | anonymous public owners | full+data | yes | 3032 | 20 | 3 | - |  | 2115 | 2159 | 984 | 21 | inline |  |
| 2x4 | anonymous public owners | full+reply | yes | 2927 | 20 | 3 | - |  | 2010 | 2060 | 984 | 21 | inline |  |
| 2x4 | anonymous public owners | full+2tree | yes | 2672 | 21 | 3 | - |  | 1722 | 1773 | 1017 | 22 | inline |  |
| 2x4 | confidential entry | min | yes | 2247 | 10 | 1 | - |  | 1798 | 1884 | 516 | 11 | inline |  |
| 2x4 | confidential entry | full | yes | 2802 | 20 | 3 | 2 |  | 1885 | 1929 | 984 | 21 | inline |  |
| 2x4 | confidential entry | full+spl | yes | 3170 | 27 | 3 | - |  | 2017 | 1933 | 1220 | 28 | inline |  |
| 2x4 | confidential entry | full+data | yes | 3200 | 20 | 3 | - |  | 2283 | 2319 | 984 | 21 | inline |  |
| 2x4 | confidential entry | full+reply | yes | 2802 | 20 | 3 | - |  | 1885 | 1929 | 984 | 21 | inline |  |
| 2x4 | confidential entry | full+2tree | yes | 2840 | 21 | 3 | - |  | 1890 | 1933 | 1017 | 22 | inline |  |
| 2x4 | anonymous entry | min | yes | 2510 | 10 | 1 | - |  | 2062 | 2147 | 515 | 11 | inline |  |
| 2x4 | anonymous entry | full | yes | 2945 | 16 | 2 | 2 |  | 2221 | 2274 | 791 | 17 | inline |  |
| 2x4 | anonymous entry | full+spl | yes | 3313 | 23 | 2 | - |  | 2353 | 2278 | 1027 | 24 | inline |  |
| 2x4 | anonymous entry | full+data | yes | 3343 | 16 | 2 | - |  | 2619 | 2664 | 791 | 17 | inline |  |
| 2x4 | anonymous entry | full+reply | yes | 3238 | 16 | 2 | - |  | 2514 | 2565 | 791 | 17 | inline |  |
| 2x4 | anonymous entry | full+2tree | yes | 2983 | 17 | 2 | - |  | 2226 | 2278 | 824 | 18 | inline |  |
| 2x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 2x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x16 | confidential signer | min | yes | 4380 | 9 | 1 | - | 284 B | 3964 | 4479 | 483 | 10 | buffered |  |
| 1x16 | confidential signer | full | yes | 4935 | 19 | 3 | none | 839 B | 4051 | 4524 | 951 | 20 | buffered |  |
| 1x16 | confidential signer | full+spl | yes | 5303 | 26 | 3 | - | 1207 B | 4183 | 4528 | 1187 | 27 | buffered |  |
| 1x16 | confidential signer | full+data | yes | 6521 | 19 | 3 | - | 2425 B | 5637 | 6078 | 951 | 20 | buffered |  |
| 1x16 | confidential signer | full+reply | yes | 4935 | 19 | 3 | - | 839 B | 4051 | 4524 | 951 | 20 | buffered |  |
| 1x16 | confidential signer | full+2tree | yes | 4973 | 20 | 3 | - | 877 B | 4056 | 4528 | 984 | 21 | buffered |  |
| 1x16 | confidential in-proof | min | yes | 4475 | 9 | 1 | - | 379 B | 4060 | 4576 | 482 | 10 | buffered |  |
| 1x16 | confidential in-proof | full | yes | 4934 | 18 | 2 | none | 838 B | 4147 | 4621 | 854 | 19 | buffered |  |
| 1x16 | confidential in-proof | full+spl | yes | 5302 | 25 | 2 | - | 1206 B | 4279 | 4625 | 1090 | 26 | buffered |  |
| 1x16 | confidential in-proof | full+data | yes | 6520 | 18 | 2 | - | 2424 B | 5733 | 6175 | 854 | 19 | buffered |  |
| 1x16 | confidential in-proof | full+reply | yes | 4934 | 18 | 2 | - | 838 B | 4147 | 4621 | 854 | 19 | buffered |  |
| 1x16 | confidential in-proof | full+2tree | yes | 4972 | 19 | 2 | - | 876 B | 4152 | 4625 | 887 | 20 | buffered |  |
| 1x16 | anonymous hidden | min | yes | 4995 | 9 | 1 | - | 899 B | 4580 | 5126 | 482 | 10 | buffered |  |
| 1x16 | anonymous hidden | full | yes | 5430 | 15 | 2 | none | 1334 B | 4739 | 5253 | 758 | 16 | buffered |  |
| 1x16 | anonymous hidden | full+spl | yes | 5798 | 22 | 2 | - | 1702 B | 4871 | 5257 | 994 | 23 | buffered |  |
| 1x16 | anonymous hidden | full+data | yes | 7016 | 15 | 2 | - | 2920 B | 6325 | 6807 | 758 | 16 | buffered |  |
| 1x16 | anonymous hidden | full+reply | yes | 6887 | 15 | 2 | - | 2791 B | 6196 | 6708 | 758 | 16 | buffered |  |
| 1x16 | anonymous hidden | full+2tree | yes | 5468 | 16 | 2 | - | 1372 B | 4744 | 5257 | 791 | 17 | buffered |  |
| 1x16 | anonymous public owners | min | yes | 4932 | 9 | 1 | - | 836 B | 4516 | 5029 | 483 | 10 | buffered |  |
| 1x16 | anonymous public owners | full | yes | 5559 | 19 | 3 | none | 1463 B | 4675 | 5156 | 951 | 20 | buffered |  |
| 1x16 | anonymous public owners | full+spl | yes | 5927 | 26 | 3 | - | 1831 B | 4807 | 5160 | 1187 | 27 | buffered |  |
| 1x16 | anonymous public owners | full+data | yes | 7145 | 19 | 3 | - | 3049 B | 6261 | 6710 | 951 | 20 | buffered |  |
| 1x16 | anonymous public owners | full+reply | yes | 7016 | 19 | 3 | - | 2920 B | 6132 | 6611 | 951 | 20 | buffered |  |
| 1x16 | anonymous public owners | full+2tree | yes | 5597 | 20 | 3 | - | 1501 B | 4680 | 5160 | 984 | 21 | buffered |  |
| 1x16 | confidential entry | min | none | 4588 | 9 | 1 | - | 492 B | 4172 | 4687 | 483 | 10 | buffered |  |
| 1x16 | confidential entry | full | none | 5143 | 19 | 3 | none | 1047 B | 4259 | 4732 | 951 | 20 | buffered |  |
| 1x16 | confidential entry | full+spl | none | 5511 | 26 | 3 | - | 1415 B | 4391 | 4736 | 1187 | 27 | buffered |  |
| 1x16 | confidential entry | full+data | none | 6729 | 19 | 3 | - | 2633 B | 5845 | 6286 | 951 | 20 | buffered |  |
| 1x16 | confidential entry | full+reply | none | 5143 | 19 | 3 | - | 1047 B | 4259 | 4732 | 951 | 20 | buffered |  |
| 1x16 | confidential entry | full+2tree | none | 5181 | 20 | 3 | - | 1085 B | 4264 | 4736 | 984 | 21 | buffered |  |
| 1x16 | anonymous entry | min | none | 5235 | 9 | 1 | - | 1139 B | 4820 | 5334 | 482 | 10 | buffered |  |
| 1x16 | anonymous entry | full | none | 5670 | 15 | 2 | none | 1574 B | 4979 | 5461 | 758 | 16 | buffered |  |
| 1x16 | anonymous entry | full+spl | none | 6038 | 22 | 2 | - | 1942 B | 5111 | 5465 | 994 | 23 | buffered |  |
| 1x16 | anonymous entry | full+data | none | 7256 | 15 | 2 | - | 3160 B | 6565 | 7015 | 758 | 16 | buffered |  |
| 1x16 | anonymous entry | full+reply | none | 7127 | 15 | 2 | - | 3031 B | 6436 | 6916 | 758 | 16 | buffered |  |
| 1x16 | anonymous entry | full+2tree | none | 5708 | 16 | 2 | - | 1612 B | 4984 | 5465 | 791 | 17 | buffered |  |
| 1x16 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 1x16 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 2x8 | confidential signer | min | yes | 2707 | 10 | 1 | - |  | 2258 | 2488 | 516 | 11 | inline |  |
| 2x8 | confidential signer | full | yes | 3262 | 20 | 3 | 2 |  | 2345 | 2533 | 984 | 21 | inline |  |
| 2x8 | confidential signer | full+spl | yes | 3630 | 27 | 3 | - |  | 2477 | 2537 | 1220 | 28 | inline |  |
| 2x8 | confidential signer | full+data | yes | 4056 | 20 | 3 | - |  | 3139 | 3311 | 984 | 21 | inline |  |
| 2x8 | confidential signer | full+reply | yes | 3262 | 20 | 3 | - |  | 2345 | 2533 | 984 | 21 | inline |  |
| 2x8 | confidential signer | full+2tree | yes | 3300 | 21 | 3 | - |  | 2350 | 2537 | 1017 | 22 | inline |  |
| 2x8 | confidential in-proof | min | yes | 2802 | 10 | 1 | - |  | 2354 | 2585 | 515 | 11 | inline |  |
| 2x8 | confidential in-proof | full | yes | 3261 | 19 | 2 | 2 |  | 2441 | 2630 | 887 | 20 | inline |  |
| 2x8 | confidential in-proof | full+spl | yes | 3629 | 26 | 2 | - |  | 2573 | 2634 | 1123 | 27 | inline |  |
| 2x8 | confidential in-proof | full+data | yes | 4055 | 19 | 2 | - |  | 3235 | 3408 | 887 | 20 | inline |  |
| 2x8 | confidential in-proof | full+reply | yes | 3261 | 19 | 2 | - |  | 2441 | 2630 | 887 | 20 | inline |  |
| 2x8 | confidential in-proof | full+2tree | yes | 3299 | 20 | 2 | - |  | 2446 | 2634 | 920 | 21 | inline |  |
| 2x8 | anonymous hidden | min | yes | 3066 | 10 | 1 | - |  | 2618 | 2879 | 515 | 11 | inline |  |
| 2x8 | anonymous hidden | full | yes | 3501 | 16 | 2 | 2 |  | 2777 | 3006 | 791 | 17 | inline |  |
| 2x8 | anonymous hidden | full+spl | yes | 3869 | 23 | 2 | - |  | 2909 | 3010 | 1027 | 24 | inline |  |
| 2x8 | anonymous hidden | full+data | yes | 4295 | 16 | 2 | - | 199 B | 3571 | 3784 | 791 | 17 | buffered |  |
| 2x8 | anonymous hidden | full+reply | yes | 4182 | 16 | 2 | - | 86 B | 3458 | 3685 | 791 | 17 | buffered |  |
| 2x8 | anonymous hidden | full+2tree | yes | 3539 | 17 | 2 | - |  | 2782 | 3010 | 824 | 18 | inline |  |
| 2x8 | anonymous public owners | min | yes | 3003 | 10 | 1 | - |  | 2554 | 2782 | 516 | 11 | inline |  |
| 2x8 | anonymous public owners | full | yes | 3630 | 20 | 3 | 2 |  | 2713 | 2909 | 984 | 21 | inline |  |
| 2x8 | anonymous public owners | full+spl | yes | 3998 | 27 | 3 | - |  | 2845 | 2913 | 1220 | 28 | inline |  |
| 2x8 | anonymous public owners | full+data | yes | 4424 | 20 | 3 | - | 328 B | 3507 | 3687 | 984 | 21 | buffered |  |
| 2x8 | anonymous public owners | full+reply | yes | 4311 | 20 | 3 | - | 215 B | 3394 | 3588 | 984 | 21 | buffered |  |
| 2x8 | anonymous public owners | full+2tree | yes | 3668 | 21 | 3 | - |  | 2718 | 2913 | 1017 | 22 | inline |  |
| 2x8 | confidential entry | min | yes | 3115 | 10 | 1 | - |  | 2666 | 2896 | 516 | 11 | inline |  |
| 2x8 | confidential entry | full | yes | 3670 | 20 | 3 | 2 |  | 2753 | 2941 | 984 | 21 | inline |  |
| 2x8 | confidential entry | full+spl | yes | 4038 | 27 | 3 | - |  | 2885 | 2945 | 1220 | 28 | inline |  |
| 2x8 | confidential entry | full+data | yes | 4464 | 20 | 3 | - | 368 B | 3547 | 3719 | 984 | 21 | buffered |  |
| 2x8 | confidential entry | full+reply | yes | 3670 | 20 | 3 | - |  | 2753 | 2941 | 984 | 21 | inline |  |
| 2x8 | confidential entry | full+2tree | yes | 3708 | 21 | 3 | - |  | 2758 | 2945 | 1017 | 22 | inline |  |
| 2x8 | anonymous entry | min | yes | 3506 | 10 | 1 | - |  | 3058 | 3287 | 515 | 11 | inline |  |
| 2x8 | anonymous entry | full | yes | 3941 | 16 | 2 | 1 |  | 3217 | 3414 | 791 | 17 | inline |  |
| 2x8 | anonymous entry | full+spl | yes | 4309 | 23 | 2 | - | 213 B | 3349 | 3418 | 1027 | 24 | buffered |  |
| 2x8 | anonymous entry | full+data | yes | 4735 | 16 | 2 | - | 639 B | 4011 | 4192 | 791 | 17 | buffered |  |
| 2x8 | anonymous entry | full+reply | yes | 4622 | 16 | 2 | - | 526 B | 3898 | 4093 | 791 | 17 | buffered |  |
| 2x8 | anonymous entry | full+2tree | yes | 3979 | 17 | 2 | - |  | 3222 | 3418 | 824 | 18 | inline |  |
| 2x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 2x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 3x2 | confidential signer | min | yes | 1470 | 11 | 1 | - |  | 988 | 1003 | 549 | 12 | inline |  |
| 3x2 | confidential signer | full | yes | 2025 | 21 | 3 | 3 |  | 1075 | 1048 | 1017 | 22 | inline |  |
| 3x2 | confidential signer | full+spl | yes | 2393 | 28 | 3 | - |  | 1207 | 1052 | 1253 | 29 | inline |  |
| 3x2 | confidential signer | full+data | yes | 2225 | 21 | 3 | - |  | 1275 | 1244 | 1017 | 22 | inline |  |
| 3x2 | confidential signer | full+reply | yes | 2025 | 21 | 3 | - |  | 1075 | 1048 | 1017 | 22 | inline |  |
| 3x2 | confidential signer | full+2tree | yes | 2063 | 22 | 3 | - |  | 1080 | 1052 | 1050 | 23 | inline |  |
| 3x2 | confidential in-proof | min | yes | 1565 | 11 | 1 | - |  | 1084 | 1100 | 548 | 12 | inline |  |
| 3x2 | confidential in-proof | full | yes | 2024 | 20 | 2 | 3 |  | 1171 | 1145 | 920 | 21 | inline |  |
| 3x2 | confidential in-proof | full+spl | yes | 2392 | 27 | 2 | - |  | 1303 | 1149 | 1156 | 28 | inline |  |
| 3x2 | confidential in-proof | full+data | yes | 2224 | 20 | 2 | - |  | 1371 | 1341 | 920 | 21 | inline |  |
| 3x2 | confidential in-proof | full+reply | yes | 2024 | 20 | 2 | - |  | 1171 | 1145 | 920 | 21 | inline |  |
| 3x2 | confidential in-proof | full+2tree | yes | 2062 | 21 | 2 | - |  | 1176 | 1149 | 953 | 22 | inline |  |
| 3x2 | anonymous hidden | min | yes | 1637 | 11 | 1 | - |  | 1156 | 1202 | 548 | 12 | inline |  |
| 3x2 | anonymous hidden | full | yes | 2072 | 17 | 2 | 3 |  | 1315 | 1329 | 824 | 18 | inline |  |
| 3x2 | anonymous hidden | full+spl | yes | 2440 | 24 | 2 | - |  | 1447 | 1333 | 1060 | 25 | inline |  |
| 3x2 | anonymous hidden | full+data | yes | 2272 | 17 | 2 | - |  | 1515 | 1525 | 824 | 18 | inline |  |
| 3x2 | anonymous hidden | full+reply | yes | 2171 | 17 | 2 | - |  | 1414 | 1426 | 824 | 18 | inline |  |
| 3x2 | anonymous hidden | full+2tree | yes | 2110 | 18 | 2 | - |  | 1320 | 1333 | 857 | 19 | inline |  |
| 3x2 | anonymous public owners | min | yes | 1574 | 11 | 1 | - |  | 1092 | 1105 | 549 | 12 | inline |  |
| 3x2 | anonymous public owners | full | yes | 2201 | 21 | 3 | 3 |  | 1251 | 1232 | 1017 | 22 | inline |  |
| 3x2 | anonymous public owners | full+spl | yes | 2569 | 28 | 3 | - |  | 1383 | 1236 | 1253 | 29 | inline |  |
| 3x2 | anonymous public owners | full+data | yes | 2401 | 21 | 3 | - |  | 1451 | 1428 | 1017 | 22 | inline |  |
| 3x2 | anonymous public owners | full+reply | yes | 2300 | 21 | 3 | - |  | 1350 | 1329 | 1017 | 22 | inline |  |
| 3x2 | anonymous public owners | full+2tree | yes | 2239 | 22 | 3 | - |  | 1256 | 1236 | 1050 | 23 | inline |  |
| 3x2 | confidential entry | min | yes | 2078 | 11 | 1 | - |  | 1596 | 1611 | 549 | 12 | inline |  |
| 3x2 | confidential entry | full | yes | 2633 | 21 | 3 | 3 |  | 1683 | 1656 | 1017 | 22 | inline |  |
| 3x2 | confidential entry | full+spl | yes | 3001 | 28 | 3 | - |  | 1815 | 1660 | 1253 | 29 | inline |  |
| 3x2 | confidential entry | full+data | yes | 2833 | 21 | 3 | - |  | 1883 | 1852 | 1017 | 22 | inline |  |
| 3x2 | confidential entry | full+reply | yes | 2633 | 21 | 3 | - |  | 1683 | 1656 | 1017 | 22 | inline |  |
| 3x2 | confidential entry | full+2tree | yes | 2671 | 22 | 3 | - |  | 1688 | 1660 | 1050 | 23 | inline |  |
| 3x2 | anonymous entry | min | yes | 2277 | 11 | 1 | - |  | 1796 | 1810 | 548 | 12 | inline |  |
| 3x2 | anonymous entry | full | yes | 2712 | 17 | 2 | 3 |  | 1955 | 1937 | 824 | 18 | inline |  |
| 3x2 | anonymous entry | full+spl | yes | 3080 | 24 | 2 | - |  | 2087 | 1941 | 1060 | 25 | inline |  |
| 3x2 | anonymous entry | full+data | yes | 2912 | 17 | 2 | - |  | 2155 | 2133 | 824 | 18 | inline |  |
| 3x2 | anonymous entry | full+reply | yes | 2811 | 17 | 2 | - |  | 2054 | 2034 | 824 | 18 | inline |  |
| 3x2 | anonymous entry | full+2tree | yes | 2750 | 18 | 2 | - |  | 1960 | 1941 | 857 | 19 | inline |  |
| 3x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 3x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 3x4 | confidential signer | min | yes | 1904 | 11 | 1 | - |  | 1422 | 1509 | 549 | 12 | inline |  |
| 3x4 | confidential signer | full | yes | 2459 | 21 | 3 | 3 |  | 1509 | 1554 | 1017 | 22 | inline |  |
| 3x4 | confidential signer | full+spl | yes | 2827 | 28 | 3 | - |  | 1641 | 1558 | 1253 | 29 | inline |  |
| 3x4 | confidential signer | full+data | yes | 2857 | 21 | 3 | - |  | 1907 | 1944 | 1017 | 22 | inline |  |
| 3x4 | confidential signer | full+reply | yes | 2459 | 21 | 3 | - |  | 1509 | 1554 | 1017 | 22 | inline |  |
| 3x4 | confidential signer | full+2tree | yes | 2497 | 22 | 3 | - |  | 1514 | 1558 | 1050 | 23 | inline |  |
| 3x4 | confidential in-proof | min | yes | 1999 | 11 | 1 | - |  | 1518 | 1606 | 548 | 12 | inline |  |
| 3x4 | confidential in-proof | full | yes | 2458 | 20 | 2 | 3 |  | 1605 | 1651 | 920 | 21 | inline |  |
| 3x4 | confidential in-proof | full+spl | yes | 2826 | 27 | 2 | - |  | 1737 | 1655 | 1156 | 28 | inline |  |
| 3x4 | confidential in-proof | full+data | yes | 2856 | 20 | 2 | - |  | 2003 | 2041 | 920 | 21 | inline |  |
| 3x4 | confidential in-proof | full+reply | yes | 2458 | 20 | 2 | - |  | 1605 | 1651 | 920 | 21 | inline |  |
| 3x4 | confidential in-proof | full+2tree | yes | 2496 | 21 | 2 | - |  | 1610 | 1655 | 953 | 22 | inline |  |
| 3x4 | anonymous hidden | min | yes | 2135 | 11 | 1 | - |  | 1654 | 1772 | 548 | 12 | inline |  |
| 3x4 | anonymous hidden | full | yes | 2570 | 17 | 2 | 3 |  | 1813 | 1899 | 824 | 18 | inline |  |
| 3x4 | anonymous hidden | full+spl | yes | 2938 | 24 | 2 | - |  | 1945 | 1903 | 1060 | 25 | inline |  |
| 3x4 | anonymous hidden | full+data | yes | 2968 | 17 | 2 | - |  | 2211 | 2289 | 824 | 18 | inline |  |
| 3x4 | anonymous hidden | full+reply | yes | 2863 | 17 | 2 | - |  | 2106 | 2190 | 824 | 18 | inline |  |
| 3x4 | anonymous hidden | full+2tree | yes | 2608 | 18 | 2 | - |  | 1818 | 1903 | 857 | 19 | inline |  |
| 3x4 | anonymous public owners | min | yes | 2072 | 11 | 1 | - |  | 1590 | 1675 | 549 | 12 | inline |  |
| 3x4 | anonymous public owners | full | yes | 2699 | 21 | 3 | 3 |  | 1749 | 1802 | 1017 | 22 | inline |  |
| 3x4 | anonymous public owners | full+spl | yes | 3067 | 28 | 3 | - |  | 1881 | 1806 | 1253 | 29 | inline |  |
| 3x4 | anonymous public owners | full+data | yes | 3097 | 21 | 3 | - |  | 2147 | 2192 | 1017 | 22 | inline |  |
| 3x4 | anonymous public owners | full+reply | yes | 2992 | 21 | 3 | - |  | 2042 | 2093 | 1017 | 22 | inline |  |
| 3x4 | anonymous public owners | full+2tree | yes | 2737 | 22 | 3 | - |  | 1754 | 1806 | 1050 | 23 | inline |  |
| 3x4 | confidential entry | min | yes | 2512 | 11 | 1 | - |  | 2030 | 2117 | 549 | 12 | inline |  |
| 3x4 | confidential entry | full | yes | 3067 | 21 | 3 | 3 |  | 2117 | 2162 | 1017 | 22 | inline |  |
| 3x4 | confidential entry | full+spl | yes | 3435 | 28 | 3 | - |  | 2249 | 2166 | 1253 | 29 | inline |  |
| 3x4 | confidential entry | full+data | yes | 3465 | 21 | 3 | - |  | 2515 | 2552 | 1017 | 22 | inline |  |
| 3x4 | confidential entry | full+reply | yes | 3067 | 21 | 3 | - |  | 2117 | 2162 | 1017 | 22 | inline |  |
| 3x4 | confidential entry | full+2tree | yes | 3105 | 22 | 3 | - |  | 2122 | 2166 | 1050 | 23 | inline |  |
| 3x4 | anonymous entry | min | yes | 2775 | 11 | 1 | - |  | 2294 | 2380 | 548 | 12 | inline |  |
| 3x4 | anonymous entry | full | yes | 3210 | 17 | 2 | 3 |  | 2453 | 2507 | 824 | 18 | inline |  |
| 3x4 | anonymous entry | full+spl | yes | 3578 | 24 | 2 | - |  | 2585 | 2511 | 1060 | 25 | inline |  |
| 3x4 | anonymous entry | full+data | yes | 3608 | 17 | 2 | - |  | 2851 | 2897 | 824 | 18 | inline |  |
| 3x4 | anonymous entry | full+reply | yes | 3503 | 17 | 2 | - |  | 2746 | 2798 | 824 | 18 | inline |  |
| 3x4 | anonymous entry | full+2tree | yes | 3248 | 18 | 2 | - |  | 2458 | 2511 | 857 | 19 | inline |  |
| 3x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 3x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 2x16 | confidential signer | min | yes | 4445 | 10 | 1 | - | 349 B | 3996 | 4512 | 516 | 11 | buffered |  |
| 2x16 | confidential signer | full | yes | 5000 | 20 | 3 | none | 904 B | 4083 | 4557 | 984 | 21 | buffered |  |
| 2x16 | confidential signer | full+spl | yes | 5368 | 27 | 3 | - | 1272 B | 4215 | 4561 | 1220 | 28 | buffered |  |
| 2x16 | confidential signer | full+data | yes | 6586 | 20 | 3 | - | 2490 B | 5669 | 6111 | 984 | 21 | buffered |  |
| 2x16 | confidential signer | full+reply | yes | 5000 | 20 | 3 | - | 904 B | 4083 | 4557 | 984 | 21 | buffered |  |
| 2x16 | confidential signer | full+2tree | yes | 5038 | 21 | 3 | - | 942 B | 4088 | 4561 | 1017 | 22 | buffered |  |
| 2x16 | confidential in-proof | min | yes | 4540 | 10 | 1 | - | 444 B | 4092 | 4609 | 515 | 11 | buffered |  |
| 2x16 | confidential in-proof | full | yes | 4999 | 19 | 2 | none | 903 B | 4179 | 4654 | 887 | 20 | buffered |  |
| 2x16 | confidential in-proof | full+spl | yes | 5367 | 26 | 2 | - | 1271 B | 4311 | 4658 | 1123 | 27 | buffered |  |
| 2x16 | confidential in-proof | full+data | yes | 6585 | 19 | 2 | - | 2489 B | 5765 | 6208 | 887 | 20 | buffered |  |
| 2x16 | confidential in-proof | full+reply | yes | 4999 | 19 | 2 | - | 903 B | 4179 | 4654 | 887 | 20 | buffered |  |
| 2x16 | confidential in-proof | full+2tree | yes | 5037 | 20 | 2 | - | 941 B | 4184 | 4658 | 920 | 21 | buffered |  |
| 2x16 | anonymous hidden | min | yes | 5060 | 10 | 1 | - | 964 B | 4612 | 5159 | 515 | 11 | buffered |  |
| 2x16 | anonymous hidden | full | yes | 5495 | 16 | 2 | none | 1399 B | 4771 | 5286 | 791 | 17 | buffered |  |
| 2x16 | anonymous hidden | full+spl | yes | 5863 | 23 | 2 | - | 1767 B | 4903 | 5290 | 1027 | 24 | buffered |  |
| 2x16 | anonymous hidden | full+data | yes | 7081 | 16 | 2 | - | 2985 B | 6357 | 6840 | 791 | 17 | buffered |  |
| 2x16 | anonymous hidden | full+reply | yes | 6952 | 16 | 2 | - | 2856 B | 6228 | 6741 | 791 | 17 | buffered |  |
| 2x16 | anonymous hidden | full+2tree | yes | 5533 | 17 | 2 | - | 1437 B | 4776 | 5290 | 824 | 18 | buffered |  |
| 2x16 | anonymous public owners | min | yes | 4997 | 10 | 1 | - | 901 B | 4548 | 5062 | 516 | 11 | buffered |  |
| 2x16 | anonymous public owners | full | yes | 5624 | 20 | 3 | none | 1528 B | 4707 | 5189 | 984 | 21 | buffered |  |
| 2x16 | anonymous public owners | full+spl | yes | 5992 | 27 | 3 | - | 1896 B | 4839 | 5193 | 1220 | 28 | buffered |  |
| 2x16 | anonymous public owners | full+data | yes | 7210 | 20 | 3 | - | 3114 B | 6293 | 6743 | 984 | 21 | buffered |  |
| 2x16 | anonymous public owners | full+reply | yes | 7081 | 20 | 3 | - | 2985 B | 6164 | 6644 | 984 | 21 | buffered |  |
| 2x16 | anonymous public owners | full+2tree | yes | 5662 | 21 | 3 | - | 1566 B | 4712 | 5193 | 1017 | 22 | buffered |  |
| 2x16 | confidential entry | min | none | 4853 | 10 | 1 | - | 757 B | 4404 | 4920 | 516 | 11 | buffered |  |
| 2x16 | confidential entry | full | none | 5408 | 20 | 3 | none | 1312 B | 4491 | 4965 | 984 | 21 | buffered |  |
| 2x16 | confidential entry | full+spl | none | 5776 | 27 | 3 | - | 1680 B | 4623 | 4969 | 1220 | 28 | buffered |  |
| 2x16 | confidential entry | full+data | none | 6994 | 20 | 3 | - | 2898 B | 6077 | 6519 | 984 | 21 | buffered |  |
| 2x16 | confidential entry | full+reply | none | 5408 | 20 | 3 | - | 1312 B | 4491 | 4965 | 984 | 21 | buffered |  |
| 2x16 | confidential entry | full+2tree | none | 5446 | 21 | 3 | - | 1350 B | 4496 | 4969 | 1017 | 22 | buffered |  |
| 2x16 | anonymous entry | min | none | 5500 | 10 | 1 | - | 1404 B | 5052 | 5567 | 515 | 11 | buffered |  |
| 2x16 | anonymous entry | full | none | 5935 | 16 | 2 | none | 1839 B | 5211 | 5694 | 791 | 17 | buffered |  |
| 2x16 | anonymous entry | full+spl | none | 6303 | 23 | 2 | - | 2207 B | 5343 | 5698 | 1027 | 24 | buffered |  |
| 2x16 | anonymous entry | full+data | none | 7521 | 16 | 2 | - | 3425 B | 6797 | 7248 | 791 | 17 | buffered |  |
| 2x16 | anonymous entry | full+reply | none | 7392 | 16 | 2 | - | 3296 B | 6668 | 7149 | 791 | 17 | buffered |  |
| 2x16 | anonymous entry | full+2tree | none | 5973 | 17 | 2 | - | 1877 B | 5216 | 5698 | 824 | 18 | buffered |  |
| 2x16 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 2x16 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 3x8 | confidential signer | min | yes | 2772 | 11 | 1 | - |  | 2290 | 2521 | 549 | 12 | inline |  |
| 3x8 | confidential signer | full | yes | 3327 | 21 | 3 | 3 |  | 2377 | 2566 | 1017 | 22 | inline |  |
| 3x8 | confidential signer | full+spl | yes | 3695 | 28 | 3 | - |  | 2509 | 2570 | 1253 | 29 | inline |  |
| 3x8 | confidential signer | full+data | yes | 4121 | 21 | 3 | - | 25 B | 3171 | 3344 | 1017 | 22 | buffered |  |
| 3x8 | confidential signer | full+reply | yes | 3327 | 21 | 3 | - |  | 2377 | 2566 | 1017 | 22 | inline |  |
| 3x8 | confidential signer | full+2tree | yes | 3365 | 22 | 3 | - |  | 2382 | 2570 | 1050 | 23 | inline |  |
| 3x8 | confidential in-proof | min | yes | 2867 | 11 | 1 | - |  | 2386 | 2618 | 548 | 12 | inline |  |
| 3x8 | confidential in-proof | full | yes | 3326 | 20 | 2 | 3 |  | 2473 | 2663 | 920 | 21 | inline |  |
| 3x8 | confidential in-proof | full+spl | yes | 3694 | 27 | 2 | - |  | 2605 | 2667 | 1156 | 28 | inline |  |
| 3x8 | confidential in-proof | full+data | yes | 4120 | 20 | 2 | - | 24 B | 3267 | 3441 | 920 | 21 | buffered |  |
| 3x8 | confidential in-proof | full+reply | yes | 3326 | 20 | 2 | - |  | 2473 | 2663 | 920 | 21 | inline |  |
| 3x8 | confidential in-proof | full+2tree | yes | 3364 | 21 | 2 | - |  | 2478 | 2667 | 953 | 22 | inline |  |
| 3x8 | anonymous hidden | min | yes | 3131 | 11 | 1 | - |  | 2650 | 2912 | 548 | 12 | inline |  |
| 3x8 | anonymous hidden | full | yes | 3566 | 17 | 2 | 3 |  | 2809 | 3039 | 824 | 18 | inline |  |
| 3x8 | anonymous hidden | full+spl | yes | 3934 | 24 | 2 | - |  | 2941 | 3043 | 1060 | 25 | inline |  |
| 3x8 | anonymous hidden | full+data | yes | 4360 | 17 | 2 | - | 264 B | 3603 | 3817 | 824 | 18 | buffered |  |
| 3x8 | anonymous hidden | full+reply | yes | 4247 | 17 | 2 | - | 151 B | 3490 | 3718 | 824 | 18 | buffered |  |
| 3x8 | anonymous hidden | full+2tree | yes | 3604 | 18 | 2 | - |  | 2814 | 3043 | 857 | 19 | inline |  |
| 3x8 | anonymous public owners | min | yes | 3068 | 11 | 1 | - |  | 2586 | 2815 | 549 | 12 | inline |  |
| 3x8 | anonymous public owners | full | yes | 3695 | 21 | 3 | 3 |  | 2745 | 2942 | 1017 | 22 | inline |  |
| 3x8 | anonymous public owners | full+spl | yes | 4063 | 28 | 3 | - |  | 2877 | 2946 | 1253 | 29 | inline |  |
| 3x8 | anonymous public owners | full+data | yes | 4489 | 21 | 3 | - | 393 B | 3539 | 3720 | 1017 | 22 | buffered |  |
| 3x8 | anonymous public owners | full+reply | yes | 4376 | 21 | 3 | - | 280 B | 3426 | 3621 | 1017 | 22 | buffered |  |
| 3x8 | anonymous public owners | full+2tree | yes | 3733 | 22 | 3 | - |  | 2750 | 2946 | 1050 | 23 | inline |  |
| 3x8 | confidential entry | min | none | 3380 | 11 | 1 | - |  | 2898 | 3129 | 549 | 12 | inline |  |
| 3x8 | confidential entry | full | none | 3935 | 21 | 3 | 2 |  | 2985 | 3174 | 1017 | 22 | inline |  |
| 3x8 | confidential entry | full+spl | none | 4303 | 28 | 3 | - | 207 B | 3117 | 3178 | 1253 | 29 | buffered |  |
| 3x8 | confidential entry | full+data | none | 4729 | 21 | 3 | - | 633 B | 3779 | 3952 | 1017 | 22 | buffered |  |
| 3x8 | confidential entry | full+reply | none | 3935 | 21 | 3 | - |  | 2985 | 3174 | 1017 | 22 | inline |  |
| 3x8 | confidential entry | full+2tree | none | 3973 | 22 | 3 | - |  | 2990 | 3178 | 1050 | 23 | inline |  |
| 3x8 | anonymous entry | min | none | 3771 | 11 | 1 | - |  | 3290 | 3520 | 548 | 12 | inline |  |
| 3x8 | anonymous entry | full | none | 4206 | 17 | 2 | none | 110 B | 3449 | 3647 | 824 | 18 | buffered |  |
| 3x8 | anonymous entry | full+spl | none | 4574 | 24 | 2 | - | 478 B | 3581 | 3651 | 1060 | 25 | buffered |  |
| 3x8 | anonymous entry | full+data | none | 5000 | 17 | 2 | - | 904 B | 4243 | 4425 | 824 | 18 | buffered |  |
| 3x8 | anonymous entry | full+reply | none | 4887 | 17 | 2 | - | 791 B | 4130 | 4326 | 824 | 18 | buffered |  |
| 3x8 | anonymous entry | full+2tree | none | 4244 | 18 | 2 | - | 148 B | 3454 | 3651 | 857 | 19 | buffered |  |
| 3x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 3x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 4x2 | confidential signer | min | yes | 1535 | 12 | 1 | - |  | 1020 | 1036 | 582 | 13 | inline |  |
| 4x2 | confidential signer | full | yes | 2090 | 22 | 3 | 4 |  | 1107 | 1081 | 1050 | 23 | inline |  |
| 4x2 | confidential signer | full+spl | yes | 2458 | 29 | 3 | - |  | 1239 | 1085 | 1286 | 30 | inline |  |
| 4x2 | confidential signer | full+data | yes | 2290 | 22 | 3 | - |  | 1307 | 1277 | 1050 | 23 | inline |  |
| 4x2 | confidential signer | full+reply | yes | 2090 | 22 | 3 | - |  | 1107 | 1081 | 1050 | 23 | inline |  |
| 4x2 | confidential signer | full+2tree | yes | 2128 | 23 | 3 | - |  | 1112 | 1085 | 1083 | 24 | inline |  |
| 4x2 | confidential in-proof | min | yes | 1630 | 12 | 1 | - |  | 1116 | 1133 | 581 | 13 | inline |  |
| 4x2 | confidential in-proof | full | yes | 2089 | 21 | 2 | 4 |  | 1203 | 1178 | 953 | 22 | inline |  |
| 4x2 | confidential in-proof | full+spl | yes | 2457 | 28 | 2 | - |  | 1335 | 1182 | 1189 | 29 | inline |  |
| 4x2 | confidential in-proof | full+data | yes | 2289 | 21 | 2 | - |  | 1403 | 1374 | 953 | 22 | inline |  |
| 4x2 | confidential in-proof | full+reply | yes | 2089 | 21 | 2 | - |  | 1203 | 1178 | 953 | 22 | inline |  |
| 4x2 | confidential in-proof | full+2tree | yes | 2127 | 22 | 2 | - |  | 1208 | 1182 | 986 | 23 | inline |  |
| 4x2 | anonymous hidden | min | yes | 1702 | 12 | 1 | - |  | 1188 | 1235 | 581 | 13 | inline |  |
| 4x2 | anonymous hidden | full | yes | 2137 | 18 | 2 | 4 |  | 1347 | 1362 | 857 | 19 | inline |  |
| 4x2 | anonymous hidden | full+spl | yes | 2505 | 25 | 2 | - |  | 1479 | 1366 | 1093 | 26 | inline |  |
| 4x2 | anonymous hidden | full+data | yes | 2337 | 18 | 2 | - |  | 1547 | 1558 | 857 | 19 | inline |  |
| 4x2 | anonymous hidden | full+reply | yes | 2236 | 18 | 2 | - |  | 1446 | 1459 | 857 | 19 | inline |  |
| 4x2 | anonymous hidden | full+2tree | yes | 2175 | 19 | 2 | - |  | 1352 | 1366 | 890 | 20 | inline |  |
| 4x2 | anonymous public owners | min | yes | 1639 | 12 | 1 | - |  | 1124 | 1138 | 582 | 13 | inline |  |
| 4x2 | anonymous public owners | full | yes | 2266 | 22 | 3 | 4 |  | 1283 | 1265 | 1050 | 23 | inline |  |
| 4x2 | anonymous public owners | full+spl | yes | 2634 | 29 | 3 | - |  | 1415 | 1269 | 1286 | 30 | inline |  |
| 4x2 | anonymous public owners | full+data | yes | 2466 | 22 | 3 | - |  | 1483 | 1461 | 1050 | 23 | inline |  |
| 4x2 | anonymous public owners | full+reply | yes | 2365 | 22 | 3 | - |  | 1382 | 1362 | 1050 | 23 | inline |  |
| 4x2 | anonymous public owners | full+2tree | yes | 2304 | 23 | 3 | - |  | 1288 | 1269 | 1083 | 24 | inline |  |
| 4x2 | confidential entry | min | yes | 2343 | 12 | 1 | - |  | 1828 | 1844 | 582 | 13 | inline |  |
| 4x2 | confidential entry | full | yes | 2898 | 22 | 3 | 4 |  | 1915 | 1889 | 1050 | 23 | inline |  |
| 4x2 | confidential entry | full+spl | yes | 3266 | 29 | 3 | - |  | 2047 | 1893 | 1286 | 30 | inline |  |
| 4x2 | confidential entry | full+data | yes | 3098 | 22 | 3 | - |  | 2115 | 2085 | 1050 | 23 | inline |  |
| 4x2 | confidential entry | full+reply | yes | 2898 | 22 | 3 | - |  | 1915 | 1889 | 1050 | 23 | inline |  |
| 4x2 | confidential entry | full+2tree | yes | 2936 | 23 | 3 | - |  | 1920 | 1893 | 1083 | 24 | inline |  |
| 4x2 | anonymous entry | min | yes | 2542 | 12 | 1 | - |  | 2028 | 2043 | 581 | 13 | inline |  |
| 4x2 | anonymous entry | full | yes | 2977 | 18 | 2 | 4 |  | 2187 | 2170 | 857 | 19 | inline |  |
| 4x2 | anonymous entry | full+spl | yes | 3345 | 25 | 2 | - |  | 2319 | 2174 | 1093 | 26 | inline |  |
| 4x2 | anonymous entry | full+data | yes | 3177 | 18 | 2 | - |  | 2387 | 2366 | 857 | 19 | inline |  |
| 4x2 | anonymous entry | full+reply | yes | 3076 | 18 | 2 | - |  | 2286 | 2267 | 857 | 19 | inline |  |
| 4x2 | anonymous entry | full+2tree | yes | 3015 | 19 | 2 | - |  | 2192 | 2174 | 890 | 20 | inline |  |
| 4x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 4x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 4x4 | confidential signer | min | yes | 1969 | 12 | 1 | - |  | 1454 | 1542 | 582 | 13 | inline |  |
| 4x4 | confidential signer | full | yes | 2524 | 22 | 3 | 4 |  | 1541 | 1587 | 1050 | 23 | inline |  |
| 4x4 | confidential signer | full+spl | yes | 2892 | 29 | 3 | - |  | 1673 | 1591 | 1286 | 30 | inline |  |
| 4x4 | confidential signer | full+data | yes | 2922 | 22 | 3 | - |  | 1939 | 1977 | 1050 | 23 | inline |  |
| 4x4 | confidential signer | full+reply | yes | 2524 | 22 | 3 | - |  | 1541 | 1587 | 1050 | 23 | inline |  |
| 4x4 | confidential signer | full+2tree | yes | 2562 | 23 | 3 | - |  | 1546 | 1591 | 1083 | 24 | inline |  |
| 4x4 | confidential in-proof | min | yes | 2064 | 12 | 1 | - |  | 1550 | 1639 | 581 | 13 | inline |  |
| 4x4 | confidential in-proof | full | yes | 2523 | 21 | 2 | 4 |  | 1637 | 1684 | 953 | 22 | inline |  |
| 4x4 | confidential in-proof | full+spl | yes | 2891 | 28 | 2 | - |  | 1769 | 1688 | 1189 | 29 | inline |  |
| 4x4 | confidential in-proof | full+data | yes | 2921 | 21 | 2 | - |  | 2035 | 2074 | 953 | 22 | inline |  |
| 4x4 | confidential in-proof | full+reply | yes | 2523 | 21 | 2 | - |  | 1637 | 1684 | 953 | 22 | inline |  |
| 4x4 | confidential in-proof | full+2tree | yes | 2561 | 22 | 2 | - |  | 1642 | 1688 | 986 | 23 | inline |  |
| 4x4 | anonymous hidden | min | yes | 2200 | 12 | 1 | - |  | 1686 | 1805 | 581 | 13 | inline |  |
| 4x4 | anonymous hidden | full | yes | 2635 | 18 | 2 | 4 |  | 1845 | 1932 | 857 | 19 | inline |  |
| 4x4 | anonymous hidden | full+spl | yes | 3003 | 25 | 2 | - |  | 1977 | 1936 | 1093 | 26 | inline |  |
| 4x4 | anonymous hidden | full+data | yes | 3033 | 18 | 2 | - |  | 2243 | 2322 | 857 | 19 | inline |  |
| 4x4 | anonymous hidden | full+reply | yes | 2928 | 18 | 2 | - |  | 2138 | 2223 | 857 | 19 | inline |  |
| 4x4 | anonymous hidden | full+2tree | yes | 2673 | 19 | 2 | - |  | 1850 | 1936 | 890 | 20 | inline |  |
| 4x4 | anonymous public owners | min | yes | 2137 | 12 | 1 | - |  | 1622 | 1708 | 582 | 13 | inline |  |
| 4x4 | anonymous public owners | full | yes | 2764 | 22 | 3 | 4 |  | 1781 | 1835 | 1050 | 23 | inline |  |
| 4x4 | anonymous public owners | full+spl | yes | 3132 | 29 | 3 | - |  | 1913 | 1839 | 1286 | 30 | inline |  |
| 4x4 | anonymous public owners | full+data | yes | 3162 | 22 | 3 | - |  | 2179 | 2225 | 1050 | 23 | inline |  |
| 4x4 | anonymous public owners | full+reply | yes | 3057 | 22 | 3 | - |  | 2074 | 2126 | 1050 | 23 | inline |  |
| 4x4 | anonymous public owners | full+2tree | yes | 2802 | 23 | 3 | - |  | 1786 | 1839 | 1083 | 24 | inline |  |
| 4x4 | confidential entry | min | yes | 2777 | 12 | 1 | - |  | 2262 | 2350 | 582 | 13 | inline |  |
| 4x4 | confidential entry | full | yes | 3332 | 22 | 3 | 4 |  | 2349 | 2395 | 1050 | 23 | inline |  |
| 4x4 | confidential entry | full+spl | yes | 3700 | 29 | 3 | - |  | 2481 | 2399 | 1286 | 30 | inline |  |
| 4x4 | confidential entry | full+data | yes | 3730 | 22 | 3 | - |  | 2747 | 2785 | 1050 | 23 | inline |  |
| 4x4 | confidential entry | full+reply | yes | 3332 | 22 | 3 | - |  | 2349 | 2395 | 1050 | 23 | inline |  |
| 4x4 | confidential entry | full+2tree | yes | 3370 | 23 | 3 | - |  | 2354 | 2399 | 1083 | 24 | inline |  |
| 4x4 | anonymous entry | min | yes | 3040 | 12 | 1 | - |  | 2526 | 2613 | 581 | 13 | inline |  |
| 4x4 | anonymous entry | full | yes | 3475 | 18 | 2 | 4 |  | 2685 | 2740 | 857 | 19 | inline |  |
| 4x4 | anonymous entry | full+spl | yes | 3843 | 25 | 2 | - |  | 2817 | 2744 | 1093 | 26 | inline |  |
| 4x4 | anonymous entry | full+data | yes | 3873 | 18 | 2 | - |  | 3083 | 3130 | 857 | 19 | inline |  |
| 4x4 | anonymous entry | full+reply | yes | 3768 | 18 | 2 | - |  | 2978 | 3031 | 857 | 19 | inline |  |
| 4x4 | anonymous entry | full+2tree | yes | 3513 | 19 | 2 | - |  | 2690 | 2744 | 890 | 20 | inline |  |
| 4x4 | delegate | min | yes | 1969 | 12 | 1 | - |  | 1454 | 1542 | 582 | 13 | inline |  |
| 4x4 | delegate | full | yes | 2312 | 18 | 2 | - |  | 1525 | 1587 | 854 | 19 | inline |  |
| 4x4 | delegate | full+spl | yes | 2552 | 25 | 2 | - |  | 1529 | 1591 | 1090 | 26 | inline |  |
| 4x4 | delegate | full+data | yes | 2710 | 18 | 2 | - |  | 1923 | 1977 | 854 | 19 | inline |  |
| 4x4 | delegate | full+reply | yes | 2312 | 18 | 2 | - |  | 1525 | 1587 | 854 | 19 | inline |  |
| 4x4 | delegate | full+2tree | yes | 2350 | 19 | 2 | - |  | 1530 | 1591 | 887 | 20 | inline |  |
| 4x4 | anonymous delegate | min | yes | 2137 | 12 | 1 | - |  | 1622 | 1708 | 582 | 13 | inline |  |
| 4x4 | anonymous delegate | full | yes | 2552 | 18 | 2 | - |  | 1765 | 1835 | 854 | 19 | inline |  |
| 4x4 | anonymous delegate | full+spl | yes | 2792 | 25 | 2 | - |  | 1769 | 1839 | 1090 | 26 | inline |  |
| 4x4 | anonymous delegate | full+data | yes | 2950 | 18 | 2 | - |  | 2163 | 2225 | 854 | 19 | inline |  |
| 4x4 | anonymous delegate | full+reply | yes | 2845 | 18 | 2 | - |  | 2058 | 2126 | 854 | 19 | inline |  |
| 4x4 | anonymous delegate | full+2tree | yes | 2590 | 19 | 2 | - |  | 1770 | 1839 | 887 | 20 | inline |  |
| 4x8 | confidential signer | min | yes | 2837 | 12 | 1 | - |  | 2322 | 2554 | 582 | 13 | inline |  |
| 4x8 | confidential signer | full | yes | 3392 | 22 | 3 | 4 |  | 2409 | 2599 | 1050 | 23 | inline |  |
| 4x8 | confidential signer | full+spl | yes | 3760 | 29 | 3 | - |  | 2541 | 2603 | 1286 | 30 | inline |  |
| 4x8 | confidential signer | full+data | yes | 4186 | 22 | 3 | - | 90 B | 3203 | 3377 | 1050 | 23 | buffered |  |
| 4x8 | confidential signer | full+reply | yes | 3392 | 22 | 3 | - |  | 2409 | 2599 | 1050 | 23 | inline |  |
| 4x8 | confidential signer | full+2tree | yes | 3430 | 23 | 3 | - |  | 2414 | 2603 | 1083 | 24 | inline |  |
| 4x8 | confidential in-proof | min | yes | 2932 | 12 | 1 | - |  | 2418 | 2651 | 581 | 13 | inline |  |
| 4x8 | confidential in-proof | full | yes | 3391 | 21 | 2 | 4 |  | 2505 | 2696 | 953 | 22 | inline |  |
| 4x8 | confidential in-proof | full+spl | yes | 3759 | 28 | 2 | - |  | 2637 | 2700 | 1189 | 29 | inline |  |
| 4x8 | confidential in-proof | full+data | yes | 4185 | 21 | 2 | - | 89 B | 3299 | 3474 | 953 | 22 | buffered |  |
| 4x8 | confidential in-proof | full+reply | yes | 3391 | 21 | 2 | - |  | 2505 | 2696 | 953 | 22 | inline |  |
| 4x8 | confidential in-proof | full+2tree | yes | 3429 | 22 | 2 | - |  | 2510 | 2700 | 986 | 23 | inline |  |
| 4x8 | anonymous hidden | min | yes | 3196 | 12 | 1 | - |  | 2682 | 2945 | 581 | 13 | inline |  |
| 4x8 | anonymous hidden | full | yes | 3631 | 18 | 2 | 4 |  | 2841 | 3072 | 857 | 19 | inline |  |
| 4x8 | anonymous hidden | full+spl | yes | 3999 | 25 | 2 | - |  | 2973 | 3076 | 1093 | 26 | inline |  |
| 4x8 | anonymous hidden | full+data | yes | 4425 | 18 | 2 | - | 329 B | 3635 | 3850 | 857 | 19 | buffered |  |
| 4x8 | anonymous hidden | full+reply | yes | 4312 | 18 | 2 | - | 216 B | 3522 | 3751 | 857 | 19 | buffered |  |
| 4x8 | anonymous hidden | full+2tree | yes | 3669 | 19 | 2 | - |  | 2846 | 3076 | 890 | 20 | inline |  |
| 4x8 | anonymous public owners | min | yes | 3133 | 12 | 1 | - |  | 2618 | 2848 | 582 | 13 | inline |  |
| 4x8 | anonymous public owners | full | yes | 3760 | 22 | 3 | 4 |  | 2777 | 2975 | 1050 | 23 | inline |  |
| 4x8 | anonymous public owners | full+spl | yes | 4128 | 29 | 3 | - | 32 B | 2909 | 2979 | 1286 | 30 | buffered |  |
| 4x8 | anonymous public owners | full+data | yes | 4554 | 22 | 3 | - | 458 B | 3571 | 3753 | 1050 | 23 | buffered |  |
| 4x8 | anonymous public owners | full+reply | yes | 4441 | 22 | 3 | - | 345 B | 3458 | 3654 | 1050 | 23 | buffered |  |
| 4x8 | anonymous public owners | full+2tree | yes | 3798 | 23 | 3 | - |  | 2782 | 2979 | 1083 | 24 | inline |  |
| 4x8 | confidential entry | min | none | 3645 | 12 | 1 | - |  | 3130 | 3362 | 582 | 13 | inline |  |
| 4x8 | confidential entry | full | none | 4200 | 22 | 3 | none | 104 B | 3217 | 3407 | 1050 | 23 | buffered |  |
| 4x8 | confidential entry | full+spl | none | 4568 | 29 | 3 | - | 472 B | 3349 | 3411 | 1286 | 30 | buffered |  |
| 4x8 | confidential entry | full+data | none | 4994 | 22 | 3 | - | 898 B | 4011 | 4185 | 1050 | 23 | buffered |  |
| 4x8 | confidential entry | full+reply | none | 4200 | 22 | 3 | - | 104 B | 3217 | 3407 | 1050 | 23 | buffered |  |
| 4x8 | confidential entry | full+2tree | none | 4238 | 23 | 3 | - | 142 B | 3222 | 3411 | 1083 | 24 | buffered |  |
| 4x8 | anonymous entry | min | none | 4036 | 12 | 1 | - |  | 3522 | 3753 | 581 | 13 | inline |  |
| 4x8 | anonymous entry | full | none | 4471 | 18 | 2 | none | 375 B | 3681 | 3880 | 857 | 19 | buffered |  |
| 4x8 | anonymous entry | full+spl | none | 4839 | 25 | 2 | - | 743 B | 3813 | 3884 | 1093 | 26 | buffered |  |
| 4x8 | anonymous entry | full+data | none | 5265 | 18 | 2 | - | 1169 B | 4475 | 4658 | 857 | 19 | buffered |  |
| 4x8 | anonymous entry | full+reply | none | 5152 | 18 | 2 | - | 1056 B | 4362 | 4559 | 857 | 19 | buffered |  |
| 4x8 | anonymous entry | full+2tree | none | 4509 | 19 | 2 | - | 413 B | 3686 | 3884 | 890 | 20 | buffered |  |
| 4x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 4x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x2 | confidential signer | min | yes | 1600 | 13 | 1 | - |  | 1052 | 1069 | 615 | 14 | inline |  |
| 5x2 | confidential signer | full | yes | 2155 | 23 | 3 | 5 |  | 1139 | 1114 | 1083 | 24 | inline |  |
| 5x2 | confidential signer | full+spl | yes | 2523 | 30 | 3 | - |  | 1271 | 1118 | 1319 | 31 | inline |  |
| 5x2 | confidential signer | full+data | yes | 2355 | 23 | 3 | - |  | 1339 | 1310 | 1083 | 24 | inline |  |
| 5x2 | confidential signer | full+reply | yes | 2155 | 23 | 3 | - |  | 1139 | 1114 | 1083 | 24 | inline |  |
| 5x2 | confidential signer | full+2tree | yes | 2193 | 24 | 3 | - |  | 1144 | 1118 | 1116 | 25 | inline |  |
| 5x2 | confidential in-proof | min | yes | 1695 | 13 | 1 | - |  | 1148 | 1166 | 614 | 14 | inline |  |
| 5x2 | confidential in-proof | full | yes | 2154 | 22 | 2 | 5 |  | 1235 | 1211 | 986 | 23 | inline |  |
| 5x2 | confidential in-proof | full+spl | yes | 2522 | 29 | 2 | - |  | 1367 | 1215 | 1222 | 30 | inline |  |
| 5x2 | confidential in-proof | full+data | yes | 2354 | 22 | 2 | - |  | 1435 | 1407 | 986 | 23 | inline |  |
| 5x2 | confidential in-proof | full+reply | yes | 2154 | 22 | 2 | - |  | 1235 | 1211 | 986 | 23 | inline |  |
| 5x2 | confidential in-proof | full+2tree | yes | 2192 | 23 | 2 | - |  | 1240 | 1215 | 1019 | 24 | inline |  |
| 5x2 | anonymous hidden | min | yes | 1767 | 13 | 1 | - |  | 1220 | 1268 | 614 | 14 | inline |  |
| 5x2 | anonymous hidden | full | yes | 2202 | 19 | 2 | 5 |  | 1379 | 1395 | 890 | 20 | inline |  |
| 5x2 | anonymous hidden | full+spl | yes | 2570 | 26 | 2 | - |  | 1511 | 1399 | 1126 | 27 | inline |  |
| 5x2 | anonymous hidden | full+data | yes | 2402 | 19 | 2 | - |  | 1579 | 1591 | 890 | 20 | inline |  |
| 5x2 | anonymous hidden | full+reply | yes | 2301 | 19 | 2 | - |  | 1478 | 1492 | 890 | 20 | inline |  |
| 5x2 | anonymous hidden | full+2tree | yes | 2240 | 20 | 2 | - |  | 1384 | 1399 | 923 | 21 | inline |  |
| 5x2 | anonymous public owners | min | yes | 1704 | 13 | 1 | - |  | 1156 | 1171 | 615 | 14 | inline |  |
| 5x2 | anonymous public owners | full | yes | 2331 | 23 | 3 | 5 |  | 1315 | 1298 | 1083 | 24 | inline |  |
| 5x2 | anonymous public owners | full+spl | yes | 2699 | 30 | 3 | - |  | 1447 | 1302 | 1319 | 31 | inline |  |
| 5x2 | anonymous public owners | full+data | yes | 2531 | 23 | 3 | - |  | 1515 | 1494 | 1083 | 24 | inline |  |
| 5x2 | anonymous public owners | full+reply | yes | 2430 | 23 | 3 | - |  | 1414 | 1395 | 1083 | 24 | inline |  |
| 5x2 | anonymous public owners | full+2tree | yes | 2369 | 24 | 3 | - |  | 1320 | 1302 | 1116 | 25 | inline |  |
| 5x2 | confidential entry | min | yes | 2608 | 13 | 1 | - |  | 2060 | 2077 | 615 | 14 | inline |  |
| 5x2 | confidential entry | full | yes | 3163 | 23 | 3 | 5 |  | 2147 | 2122 | 1083 | 24 | inline |  |
| 5x2 | confidential entry | full+spl | yes | 3531 | 30 | 3 | - |  | 2279 | 2126 | 1319 | 31 | inline |  |
| 5x2 | confidential entry | full+data | yes | 3363 | 23 | 3 | - |  | 2347 | 2318 | 1083 | 24 | inline |  |
| 5x2 | confidential entry | full+reply | yes | 3163 | 23 | 3 | - |  | 2147 | 2122 | 1083 | 24 | inline |  |
| 5x2 | confidential entry | full+2tree | yes | 3201 | 24 | 3 | - |  | 2152 | 2126 | 1116 | 25 | inline |  |
| 5x2 | anonymous entry | min | yes | 2807 | 13 | 1 | - |  | 2260 | 2276 | 614 | 14 | inline |  |
| 5x2 | anonymous entry | full | yes | 3242 | 19 | 2 | 5 |  | 2419 | 2403 | 890 | 20 | inline |  |
| 5x2 | anonymous entry | full+spl | yes | 3610 | 26 | 2 | - |  | 2551 | 2407 | 1126 | 27 | inline |  |
| 5x2 | anonymous entry | full+data | yes | 3442 | 19 | 2 | - |  | 2619 | 2599 | 890 | 20 | inline |  |
| 5x2 | anonymous entry | full+reply | yes | 3341 | 19 | 2 | - |  | 2518 | 2500 | 890 | 20 | inline |  |
| 5x2 | anonymous entry | full+2tree | yes | 3280 | 20 | 2 | - |  | 2424 | 2407 | 923 | 21 | inline |  |
| 5x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x4 | confidential signer | min | yes | 2034 | 13 | 1 | - |  | 1486 | 1575 | 615 | 14 | inline |  |
| 5x4 | confidential signer | full | yes | 2589 | 23 | 3 | 5 |  | 1573 | 1620 | 1083 | 24 | inline |  |
| 5x4 | confidential signer | full+spl | yes | 2957 | 30 | 3 | - |  | 1705 | 1624 | 1319 | 31 | inline |  |
| 5x4 | confidential signer | full+data | yes | 2987 | 23 | 3 | - |  | 1971 | 2010 | 1083 | 24 | inline |  |
| 5x4 | confidential signer | full+reply | yes | 2589 | 23 | 3 | - |  | 1573 | 1620 | 1083 | 24 | inline |  |
| 5x4 | confidential signer | full+2tree | yes | 2627 | 24 | 3 | - |  | 1578 | 1624 | 1116 | 25 | inline |  |
| 5x4 | confidential in-proof | min | yes | 2129 | 13 | 1 | - |  | 1582 | 1672 | 614 | 14 | inline |  |
| 5x4 | confidential in-proof | full | yes | 2588 | 22 | 2 | 5 |  | 1669 | 1717 | 986 | 23 | inline |  |
| 5x4 | confidential in-proof | full+spl | yes | 2956 | 29 | 2 | - |  | 1801 | 1721 | 1222 | 30 | inline |  |
| 5x4 | confidential in-proof | full+data | yes | 2986 | 22 | 2 | - |  | 2067 | 2107 | 986 | 23 | inline |  |
| 5x4 | confidential in-proof | full+reply | yes | 2588 | 22 | 2 | - |  | 1669 | 1717 | 986 | 23 | inline |  |
| 5x4 | confidential in-proof | full+2tree | yes | 2626 | 23 | 2 | - |  | 1674 | 1721 | 1019 | 24 | inline |  |
| 5x4 | anonymous hidden | min | yes | 2265 | 13 | 1 | - |  | 1718 | 1838 | 614 | 14 | inline |  |
| 5x4 | anonymous hidden | full | yes | 2700 | 19 | 2 | 5 |  | 1877 | 1965 | 890 | 20 | inline |  |
| 5x4 | anonymous hidden | full+spl | yes | 3068 | 26 | 2 | - |  | 2009 | 1969 | 1126 | 27 | inline |  |
| 5x4 | anonymous hidden | full+data | yes | 3098 | 19 | 2 | - |  | 2275 | 2355 | 890 | 20 | inline |  |
| 5x4 | anonymous hidden | full+reply | yes | 2993 | 19 | 2 | - |  | 2170 | 2256 | 890 | 20 | inline |  |
| 5x4 | anonymous hidden | full+2tree | yes | 2738 | 20 | 2 | - |  | 1882 | 1969 | 923 | 21 | inline |  |
| 5x4 | anonymous public owners | min | yes | 2202 | 13 | 1 | - |  | 1654 | 1741 | 615 | 14 | inline |  |
| 5x4 | anonymous public owners | full | yes | 2829 | 23 | 3 | 5 |  | 1813 | 1868 | 1083 | 24 | inline |  |
| 5x4 | anonymous public owners | full+spl | yes | 3197 | 30 | 3 | - |  | 1945 | 1872 | 1319 | 31 | inline |  |
| 5x4 | anonymous public owners | full+data | yes | 3227 | 23 | 3 | - |  | 2211 | 2258 | 1083 | 24 | inline |  |
| 5x4 | anonymous public owners | full+reply | yes | 3122 | 23 | 3 | - |  | 2106 | 2159 | 1083 | 24 | inline |  |
| 5x4 | anonymous public owners | full+2tree | yes | 2867 | 24 | 3 | - |  | 1818 | 1872 | 1116 | 25 | inline |  |
| 5x4 | confidential entry | min | yes | 3042 | 13 | 1 | - |  | 2494 | 2583 | 615 | 14 | inline |  |
| 5x4 | confidential entry | full | yes | 3597 | 23 | 3 | 5 |  | 2581 | 2628 | 1083 | 24 | inline |  |
| 5x4 | confidential entry | full+spl | yes | 3965 | 30 | 3 | - |  | 2713 | 2632 | 1319 | 31 | inline |  |
| 5x4 | confidential entry | full+data | yes | 3995 | 23 | 3 | - |  | 2979 | 3018 | 1083 | 24 | inline |  |
| 5x4 | confidential entry | full+reply | yes | 3597 | 23 | 3 | - |  | 2581 | 2628 | 1083 | 24 | inline |  |
| 5x4 | confidential entry | full+2tree | yes | 3635 | 24 | 3 | - |  | 2586 | 2632 | 1116 | 25 | inline |  |
| 5x4 | anonymous entry | min | yes | 3305 | 13 | 1 | - |  | 2758 | 2846 | 614 | 14 | inline |  |
| 5x4 | anonymous entry | full | yes | 3740 | 19 | 2 | 3 |  | 2917 | 2973 | 890 | 20 | inline |  |
| 5x4 | anonymous entry | full+spl | yes | 4108 | 26 | 2 | - | 12 B | 3049 | 2977 | 1126 | 27 | buffered |  |
| 5x4 | anonymous entry | full+data | yes | 4138 | 19 | 2 | - | 42 B | 3315 | 3363 | 890 | 20 | buffered |  |
| 5x4 | anonymous entry | full+reply | yes | 4033 | 19 | 2 | - |  | 3210 | 3264 | 890 | 20 | inline |  |
| 5x4 | anonymous entry | full+2tree | yes | 3778 | 20 | 2 | - |  | 2922 | 2977 | 923 | 21 | inline |  |
| 5x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 4x16 | confidential signer | min | yes | 4575 | 12 | 1 | - | 479 B | 4060 | 4578 | 582 | 13 | buffered |  |
| 4x16 | confidential signer | full | yes | 5130 | 22 | 3 | none | 1034 B | 4147 | 4623 | 1050 | 23 | buffered |  |
| 4x16 | confidential signer | full+spl | yes | 5498 | 29 | 3 | - | 1402 B | 4279 | 4627 | 1286 | 30 | buffered |  |
| 4x16 | confidential signer | full+data | yes | 6716 | 22 | 3 | - | 2620 B | 5733 | 6177 | 1050 | 23 | buffered |  |
| 4x16 | confidential signer | full+reply | yes | 5130 | 22 | 3 | - | 1034 B | 4147 | 4623 | 1050 | 23 | buffered |  |
| 4x16 | confidential signer | full+2tree | yes | 5168 | 23 | 3 | - | 1072 B | 4152 | 4627 | 1083 | 24 | buffered |  |
| 4x16 | confidential in-proof | min | yes | 4670 | 12 | 1 | - | 574 B | 4156 | 4675 | 581 | 13 | buffered |  |
| 4x16 | confidential in-proof | full | yes | 5129 | 21 | 2 | none | 1033 B | 4243 | 4720 | 953 | 22 | buffered |  |
| 4x16 | confidential in-proof | full+spl | yes | 5497 | 28 | 2 | - | 1401 B | 4375 | 4724 | 1189 | 29 | buffered |  |
| 4x16 | confidential in-proof | full+data | yes | 6715 | 21 | 2 | - | 2619 B | 5829 | 6274 | 953 | 22 | buffered |  |
| 4x16 | confidential in-proof | full+reply | yes | 5129 | 21 | 2 | - | 1033 B | 4243 | 4720 | 953 | 22 | buffered |  |
| 4x16 | confidential in-proof | full+2tree | yes | 5167 | 22 | 2 | - | 1071 B | 4248 | 4724 | 986 | 23 | buffered |  |
| 4x16 | anonymous hidden | min | yes | 5190 | 12 | 1 | - | 1094 B | 4676 | 5225 | 581 | 13 | buffered |  |
| 4x16 | anonymous hidden | full | yes | 5625 | 18 | 2 | none | 1529 B | 4835 | 5352 | 857 | 19 | buffered |  |
| 4x16 | anonymous hidden | full+spl | yes | 5993 | 25 | 2 | - | 1897 B | 4967 | 5356 | 1093 | 26 | buffered |  |
| 4x16 | anonymous hidden | full+data | yes | 7211 | 18 | 2 | - | 3115 B | 6421 | 6906 | 857 | 19 | buffered |  |
| 4x16 | anonymous hidden | full+reply | yes | 7082 | 18 | 2 | - | 2986 B | 6292 | 6807 | 857 | 19 | buffered |  |
| 4x16 | anonymous hidden | full+2tree | yes | 5663 | 19 | 2 | - | 1567 B | 4840 | 5356 | 890 | 20 | buffered |  |
| 4x16 | anonymous public owners | min | yes | 5127 | 12 | 1 | - | 1031 B | 4612 | 5128 | 582 | 13 | buffered |  |
| 4x16 | anonymous public owners | full | yes | 5754 | 22 | 3 | none | 1658 B | 4771 | 5255 | 1050 | 23 | buffered |  |
| 4x16 | anonymous public owners | full+spl | yes | 6122 | 29 | 3 | - | 2026 B | 4903 | 5259 | 1286 | 30 | buffered |  |
| 4x16 | anonymous public owners | full+data | yes | 7340 | 22 | 3 | - | 3244 B | 6357 | 6809 | 1050 | 23 | buffered |  |
| 4x16 | anonymous public owners | full+reply | yes | 7211 | 22 | 3 | - | 3115 B | 6228 | 6710 | 1050 | 23 | buffered |  |
| 4x16 | anonymous public owners | full+2tree | yes | 5792 | 23 | 3 | - | 1696 B | 4776 | 5259 | 1083 | 24 | buffered |  |
| 4x16 | confidential entry | min | none | 5383 | 12 | 1 | - | 1287 B | 4868 | 5386 | 582 | 13 | buffered |  |
| 4x16 | confidential entry | full | none | 5938 | 22 | 3 | none | 1842 B | 4955 | 5431 | 1050 | 23 | buffered |  |
| 4x16 | confidential entry | full+spl | none | 6306 | 29 | 3 | - | 2210 B | 5087 | 5435 | 1286 | 30 | buffered |  |
| 4x16 | confidential entry | full+data | none | 7524 | 22 | 3 | - | 3428 B | 6541 | 6985 | 1050 | 23 | buffered |  |
| 4x16 | confidential entry | full+reply | none | 5938 | 22 | 3 | - | 1842 B | 4955 | 5431 | 1050 | 23 | buffered |  |
| 4x16 | confidential entry | full+2tree | none | 5976 | 23 | 3 | - | 1880 B | 4960 | 5435 | 1083 | 24 | buffered |  |
| 4x16 | anonymous entry | min | none | 6030 | 12 | 1 | - | 1934 B | 5516 | 6033 | 581 | 13 | buffered |  |
| 4x16 | anonymous entry | full | none | 6465 | 18 | 2 | none | 2369 B | 5675 | 6160 | 857 | 19 | buffered |  |
| 4x16 | anonymous entry | full+spl | none | 6833 | 25 | 2 | - | 2737 B | 5807 | 6164 | 1093 | 26 | buffered |  |
| 4x16 | anonymous entry | full+data | none | 8051 | 18 | 2 | - | 3955 B | 7261 | 7714 | 857 | 19 | buffered |  |
| 4x16 | anonymous entry | full+reply | none | 7922 | 18 | 2 | - | 3826 B | 7132 | 7615 | 857 | 19 | buffered |  |
| 4x16 | anonymous entry | full+2tree | none | 6503 | 19 | 2 | - | 2407 B | 5680 | 6164 | 890 | 20 | buffered |  |
| 4x16 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 4x16 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x8 | confidential signer | min | yes | 2902 | 13 | 1 | - |  | 2354 | 2587 | 615 | 14 | inline |  |
| 5x8 | confidential signer | full | yes | 3457 | 23 | 3 | 5 |  | 2441 | 2632 | 1083 | 24 | inline |  |
| 5x8 | confidential signer | full+spl | yes | 3825 | 30 | 3 | - |  | 2573 | 2636 | 1319 | 31 | inline |  |
| 5x8 | confidential signer | full+data | yes | 4251 | 23 | 3 | - | 155 B | 3235 | 3410 | 1083 | 24 | buffered |  |
| 5x8 | confidential signer | full+reply | yes | 3457 | 23 | 3 | - |  | 2441 | 2632 | 1083 | 24 | inline |  |
| 5x8 | confidential signer | full+2tree | yes | 3495 | 24 | 3 | - |  | 2446 | 2636 | 1116 | 25 | inline |  |
| 5x8 | confidential in-proof | min | yes | 2997 | 13 | 1 | - |  | 2450 | 2684 | 614 | 14 | inline |  |
| 5x8 | confidential in-proof | full | yes | 3456 | 22 | 2 | 5 |  | 2537 | 2729 | 986 | 23 | inline |  |
| 5x8 | confidential in-proof | full+spl | yes | 3824 | 29 | 2 | - |  | 2669 | 2733 | 1222 | 30 | inline |  |
| 5x8 | confidential in-proof | full+data | yes | 4250 | 22 | 2 | - | 154 B | 3331 | 3507 | 986 | 23 | buffered |  |
| 5x8 | confidential in-proof | full+reply | yes | 3456 | 22 | 2 | - |  | 2537 | 2729 | 986 | 23 | inline |  |
| 5x8 | confidential in-proof | full+2tree | yes | 3494 | 23 | 2 | - |  | 2542 | 2733 | 1019 | 24 | inline |  |
| 5x8 | anonymous hidden | min | yes | 3261 | 13 | 1 | - |  | 2714 | 2978 | 614 | 14 | inline |  |
| 5x8 | anonymous hidden | full | yes | 3696 | 19 | 2 | 4 |  | 2873 | 3105 | 890 | 20 | inline |  |
| 5x8 | anonymous hidden | full+spl | yes | 4064 | 26 | 2 | - |  | 3005 | 3109 | 1126 | 27 | inline |  |
| 5x8 | anonymous hidden | full+data | yes | 4490 | 19 | 2 | - | 394 B | 3667 | 3883 | 890 | 20 | buffered |  |
| 5x8 | anonymous hidden | full+reply | yes | 4377 | 19 | 2 | - | 281 B | 3554 | 3784 | 890 | 20 | buffered |  |
| 5x8 | anonymous hidden | full+2tree | yes | 3734 | 20 | 2 | - |  | 2878 | 3109 | 923 | 21 | inline |  |
| 5x8 | anonymous public owners | min | yes | 3198 | 13 | 1 | - |  | 2650 | 2881 | 615 | 14 | inline |  |
| 5x8 | anonymous public owners | full | yes | 3825 | 23 | 3 | 3 |  | 2809 | 3008 | 1083 | 24 | inline |  |
| 5x8 | anonymous public owners | full+spl | yes | 4193 | 30 | 3 | - | 97 B | 2941 | 3012 | 1319 | 31 | buffered |  |
| 5x8 | anonymous public owners | full+data | yes | 4619 | 23 | 3 | - | 523 B | 3603 | 3786 | 1083 | 24 | buffered |  |
| 5x8 | anonymous public owners | full+reply | yes | 4506 | 23 | 3 | - | 410 B | 3490 | 3687 | 1083 | 24 | buffered |  |
| 5x8 | anonymous public owners | full+2tree | yes | 3863 | 24 | 3 | - |  | 2814 | 3012 | 1116 | 25 | inline |  |
| 5x8 | confidential entry | min | none | 3910 | 13 | 1 | - |  | 3362 | 3595 | 615 | 14 | inline |  |
| 5x8 | confidential entry | full | none | 4465 | 23 | 3 | none | 369 B | 3449 | 3640 | 1083 | 24 | buffered |  |
| 5x8 | confidential entry | full+spl | none | 4833 | 30 | 3 | - | 737 B | 3581 | 3644 | 1319 | 31 | buffered |  |
| 5x8 | confidential entry | full+data | none | 5259 | 23 | 3 | - | 1163 B | 4243 | 4418 | 1083 | 24 | buffered |  |
| 5x8 | confidential entry | full+reply | none | 4465 | 23 | 3 | - | 369 B | 3449 | 3640 | 1083 | 24 | buffered |  |
| 5x8 | confidential entry | full+2tree | none | 4503 | 24 | 3 | - | 407 B | 3454 | 3644 | 1116 | 25 | buffered |  |
| 5x8 | anonymous entry | min | none | 4301 | 13 | 1 | - | 205 B | 3754 | 3986 | 614 | 14 | buffered |  |
| 5x8 | anonymous entry | full | none | 4736 | 19 | 2 | none | 640 B | 3913 | 4113 | 890 | 20 | buffered |  |
| 5x8 | anonymous entry | full+spl | none | 5104 | 26 | 2 | - | 1008 B | 4045 | 4117 | 1126 | 27 | buffered |  |
| 5x8 | anonymous entry | full+data | none | 5530 | 19 | 2 | - | 1434 B | 4707 | 4891 | 890 | 20 | buffered |  |
| 5x8 | anonymous entry | full+reply | none | 5417 | 19 | 2 | - | 1321 B | 4594 | 4792 | 890 | 20 | buffered |  |
| 5x8 | anonymous entry | full+2tree | none | 4774 | 20 | 2 | - | 678 B | 3918 | 4117 | 923 | 21 | buffered |  |
| 5x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 6x2 | confidential signer | min | yes | 1665 | 14 | 1 | - |  | 1084 | 1102 | 648 | 15 | inline |  |
| 6x2 | confidential signer | full | yes | 2220 | 24 | 3 | 6 |  | 1171 | 1147 | 1116 | 25 | inline |  |
| 6x2 | confidential signer | full+spl | yes | 2588 | 31 | 3 | - |  | 1303 | 1151 | 1352 | 32 | inline |  |
| 6x2 | confidential signer | full+data | yes | 2420 | 24 | 3 | - |  | 1371 | 1343 | 1116 | 25 | inline |  |
| 6x2 | confidential signer | full+reply | yes | 2220 | 24 | 3 | - |  | 1171 | 1147 | 1116 | 25 | inline |  |
| 6x2 | confidential signer | full+2tree | yes | 2258 | 25 | 3 | - |  | 1176 | 1151 | 1149 | 26 | inline |  |
| 6x2 | confidential in-proof | min | yes | 1760 | 14 | 1 | - |  | 1180 | 1199 | 647 | 15 | inline |  |
| 6x2 | confidential in-proof | full | yes | 2219 | 23 | 2 | 6 |  | 1267 | 1244 | 1019 | 24 | inline |  |
| 6x2 | confidential in-proof | full+spl | yes | 2587 | 30 | 2 | - |  | 1399 | 1248 | 1255 | 31 | inline |  |
| 6x2 | confidential in-proof | full+data | yes | 2419 | 23 | 2 | - |  | 1467 | 1440 | 1019 | 24 | inline |  |
| 6x2 | confidential in-proof | full+reply | yes | 2219 | 23 | 2 | - |  | 1267 | 1244 | 1019 | 24 | inline |  |
| 6x2 | confidential in-proof | full+2tree | yes | 2257 | 24 | 2 | - |  | 1272 | 1248 | 1052 | 25 | inline |  |
| 6x2 | anonymous hidden | min | yes | 1832 | 14 | 1 | - |  | 1252 | 1301 | 647 | 15 | inline |  |
| 6x2 | anonymous hidden | full | yes | 2267 | 20 | 2 | 6 |  | 1411 | 1428 | 923 | 21 | inline |  |
| 6x2 | anonymous hidden | full+spl | yes | 2635 | 27 | 2 | - |  | 1543 | 1432 | 1159 | 28 | inline |  |
| 6x2 | anonymous hidden | full+data | yes | 2467 | 20 | 2 | - |  | 1611 | 1624 | 923 | 21 | inline |  |
| 6x2 | anonymous hidden | full+reply | yes | 2366 | 20 | 2 | - |  | 1510 | 1525 | 923 | 21 | inline |  |
| 6x2 | anonymous hidden | full+2tree | yes | 2305 | 21 | 2 | - |  | 1416 | 1432 | 956 | 22 | inline |  |
| 6x2 | anonymous public owners | min | yes | 1769 | 14 | 1 | - |  | 1188 | 1204 | 648 | 15 | inline |  |
| 6x2 | anonymous public owners | full | yes | 2396 | 24 | 3 | 6 |  | 1347 | 1331 | 1116 | 25 | inline |  |
| 6x2 | anonymous public owners | full+spl | yes | 2764 | 31 | 3 | - |  | 1479 | 1335 | 1352 | 32 | inline |  |
| 6x2 | anonymous public owners | full+data | yes | 2596 | 24 | 3 | - |  | 1547 | 1527 | 1116 | 25 | inline |  |
| 6x2 | anonymous public owners | full+reply | yes | 2495 | 24 | 3 | - |  | 1446 | 1428 | 1116 | 25 | inline |  |
| 6x2 | anonymous public owners | full+2tree | yes | 2434 | 25 | 3 | - |  | 1352 | 1335 | 1149 | 26 | inline |  |
| 6x2 | confidential entry | min | yes | 2873 | 14 | 1 | - |  | 2292 | 2310 | 648 | 15 | inline |  |
| 6x2 | confidential entry | full | yes | 3428 | 24 | 3 | 6 |  | 2379 | 2355 | 1116 | 25 | inline |  |
| 6x2 | confidential entry | full+spl | yes | 3796 | 31 | 3 | - |  | 2511 | 2359 | 1352 | 32 | inline |  |
| 6x2 | confidential entry | full+data | yes | 3628 | 24 | 3 | - |  | 2579 | 2551 | 1116 | 25 | inline |  |
| 6x2 | confidential entry | full+reply | yes | 3428 | 24 | 3 | - |  | 2379 | 2355 | 1116 | 25 | inline |  |
| 6x2 | confidential entry | full+2tree | yes | 3466 | 25 | 3 | - |  | 2384 | 2359 | 1149 | 26 | inline |  |
| 6x2 | anonymous entry | min | yes | 3072 | 14 | 1 | - |  | 2492 | 2509 | 647 | 15 | inline |  |
| 6x2 | anonymous entry | full | yes | 3507 | 20 | 2 | 6 |  | 2651 | 2636 | 923 | 21 | inline |  |
| 6x2 | anonymous entry | full+spl | yes | 3875 | 27 | 2 | - |  | 2783 | 2640 | 1159 | 28 | inline |  |
| 6x2 | anonymous entry | full+data | yes | 3707 | 20 | 2 | - |  | 2851 | 2832 | 923 | 21 | inline |  |
| 6x2 | anonymous entry | full+reply | yes | 3606 | 20 | 2 | - |  | 2750 | 2733 | 923 | 21 | inline |  |
| 6x2 | anonymous entry | full+2tree | yes | 3545 | 21 | 2 | - |  | 2656 | 2640 | 956 | 22 | inline |  |
| 6x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 6x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 6x4 | confidential signer | min | yes | 2099 | 14 | 1 | - |  | 1518 | 1608 | 648 | 15 | inline |  |
| 6x4 | confidential signer | full | yes | 2654 | 24 | 3 | 6 |  | 1605 | 1653 | 1116 | 25 | inline |  |
| 6x4 | confidential signer | full+spl | yes | 3022 | 31 | 3 | - |  | 1737 | 1657 | 1352 | 32 | inline |  |
| 6x4 | confidential signer | full+data | yes | 3052 | 24 | 3 | - |  | 2003 | 2043 | 1116 | 25 | inline |  |
| 6x4 | confidential signer | full+reply | yes | 2654 | 24 | 3 | - |  | 1605 | 1653 | 1116 | 25 | inline |  |
| 6x4 | confidential signer | full+2tree | yes | 2692 | 25 | 3 | - |  | 1610 | 1657 | 1149 | 26 | inline |  |
| 6x4 | confidential in-proof | min | yes | 2194 | 14 | 1 | - |  | 1614 | 1705 | 647 | 15 | inline |  |
| 6x4 | confidential in-proof | full | yes | 2653 | 23 | 2 | 6 |  | 1701 | 1750 | 1019 | 24 | inline |  |
| 6x4 | confidential in-proof | full+spl | yes | 3021 | 30 | 2 | - |  | 1833 | 1754 | 1255 | 31 | inline |  |
| 6x4 | confidential in-proof | full+data | yes | 3051 | 23 | 2 | - |  | 2099 | 2140 | 1019 | 24 | inline |  |
| 6x4 | confidential in-proof | full+reply | yes | 2653 | 23 | 2 | - |  | 1701 | 1750 | 1019 | 24 | inline |  |
| 6x4 | confidential in-proof | full+2tree | yes | 2691 | 24 | 2 | - |  | 1706 | 1754 | 1052 | 25 | inline |  |
| 6x4 | anonymous hidden | min | yes | 2330 | 14 | 1 | - |  | 1750 | 1871 | 647 | 15 | inline |  |
| 6x4 | anonymous hidden | full | yes | 2765 | 20 | 2 | 6 |  | 1909 | 1998 | 923 | 21 | inline |  |
| 6x4 | anonymous hidden | full+spl | yes | 3133 | 27 | 2 | - |  | 2041 | 2002 | 1159 | 28 | inline |  |
| 6x4 | anonymous hidden | full+data | yes | 3163 | 20 | 2 | - |  | 2307 | 2388 | 923 | 21 | inline |  |
| 6x4 | anonymous hidden | full+reply | yes | 3058 | 20 | 2 | - |  | 2202 | 2289 | 923 | 21 | inline |  |
| 6x4 | anonymous hidden | full+2tree | yes | 2803 | 21 | 2 | - |  | 1914 | 2002 | 956 | 22 | inline |  |
| 6x4 | anonymous public owners | min | yes | 2267 | 14 | 1 | - |  | 1686 | 1774 | 648 | 15 | inline |  |
| 6x4 | anonymous public owners | full | yes | 2894 | 24 | 3 | 6 |  | 1845 | 1901 | 1116 | 25 | inline |  |
| 6x4 | anonymous public owners | full+spl | yes | 3262 | 31 | 3 | - |  | 1977 | 1905 | 1352 | 32 | inline |  |
| 6x4 | anonymous public owners | full+data | yes | 3292 | 24 | 3 | - |  | 2243 | 2291 | 1116 | 25 | inline |  |
| 6x4 | anonymous public owners | full+reply | yes | 3187 | 24 | 3 | - |  | 2138 | 2192 | 1116 | 25 | inline |  |
| 6x4 | anonymous public owners | full+2tree | yes | 2932 | 25 | 3 | - |  | 1850 | 1905 | 1149 | 26 | inline |  |
| 6x4 | confidential entry | min | yes | 3307 | 14 | 1 | - |  | 2726 | 2816 | 648 | 15 | inline |  |
| 6x4 | confidential entry | full | yes | 3862 | 24 | 3 | 3 |  | 2813 | 2861 | 1116 | 25 | inline |  |
| 6x4 | confidential entry | full+spl | yes | 4230 | 31 | 3 | - | 134 B | 2945 | 2865 | 1352 | 32 | buffered |  |
| 6x4 | confidential entry | full+data | yes | 4260 | 24 | 3 | - | 164 B | 3211 | 3251 | 1116 | 25 | buffered |  |
| 6x4 | confidential entry | full+reply | yes | 3862 | 24 | 3 | - |  | 2813 | 2861 | 1116 | 25 | inline |  |
| 6x4 | confidential entry | full+2tree | yes | 3900 | 25 | 3 | - |  | 2818 | 2865 | 1149 | 26 | inline |  |
| 6x4 | anonymous entry | min | yes | 3570 | 14 | 1 | - |  | 2990 | 3079 | 647 | 15 | inline |  |
| 6x4 | anonymous entry | full | yes | 4005 | 20 | 2 | 0 |  | 3149 | 3206 | 923 | 21 | inline |  |
| 6x4 | anonymous entry | full+spl | yes | 4373 | 27 | 2 | - | 277 B | 3281 | 3210 | 1159 | 28 | buffered |  |
| 6x4 | anonymous entry | full+data | yes | 4403 | 20 | 2 | - | 307 B | 3547 | 3596 | 923 | 21 | buffered |  |
| 6x4 | anonymous entry | full+reply | yes | 4298 | 20 | 2 | - | 202 B | 3442 | 3497 | 923 | 21 | buffered |  |
| 6x4 | anonymous entry | full+2tree | yes | 4043 | 21 | 2 | - |  | 3154 | 3210 | 956 | 22 | inline |  |
| 6x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 6x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x16 | confidential signer | min | yes | 4640 | 13 | 1 | - | 544 B | 4092 | 4611 | 615 | 14 | buffered |  |
| 5x16 | confidential signer | full | yes | 5195 | 23 | 3 | none | 1099 B | 4179 | 4656 | 1083 | 24 | buffered |  |
| 5x16 | confidential signer | full+spl | yes | 5563 | 30 | 3 | - | 1467 B | 4311 | 4660 | 1319 | 31 | buffered |  |
| 5x16 | confidential signer | full+data | yes | 6781 | 23 | 3 | - | 2685 B | 5765 | 6210 | 1083 | 24 | buffered |  |
| 5x16 | confidential signer | full+reply | yes | 5195 | 23 | 3 | - | 1099 B | 4179 | 4656 | 1083 | 24 | buffered |  |
| 5x16 | confidential signer | full+2tree | yes | 5233 | 24 | 3 | - | 1137 B | 4184 | 4660 | 1116 | 25 | buffered |  |
| 5x16 | confidential in-proof | min | yes | 4735 | 13 | 1 | - | 639 B | 4188 | 4708 | 614 | 14 | buffered |  |
| 5x16 | confidential in-proof | full | yes | 5194 | 22 | 2 | none | 1098 B | 4275 | 4753 | 986 | 23 | buffered |  |
| 5x16 | confidential in-proof | full+spl | yes | 5562 | 29 | 2 | - | 1466 B | 4407 | 4757 | 1222 | 30 | buffered |  |
| 5x16 | confidential in-proof | full+data | yes | 6780 | 22 | 2 | - | 2684 B | 5861 | 6307 | 986 | 23 | buffered |  |
| 5x16 | confidential in-proof | full+reply | yes | 5194 | 22 | 2 | - | 1098 B | 4275 | 4753 | 986 | 23 | buffered |  |
| 5x16 | confidential in-proof | full+2tree | yes | 5232 | 23 | 2 | - | 1136 B | 4280 | 4757 | 1019 | 24 | buffered |  |
| 5x16 | anonymous hidden | min | yes | 5255 | 13 | 1 | - | 1159 B | 4708 | 5258 | 614 | 14 | buffered |  |
| 5x16 | anonymous hidden | full | yes | 5690 | 19 | 2 | none | 1594 B | 4867 | 5385 | 890 | 20 | buffered |  |
| 5x16 | anonymous hidden | full+spl | yes | 6058 | 26 | 2 | - | 1962 B | 4999 | 5389 | 1126 | 27 | buffered |  |
| 5x16 | anonymous hidden | full+data | yes | 7276 | 19 | 2 | - | 3180 B | 6453 | 6939 | 890 | 20 | buffered |  |
| 5x16 | anonymous hidden | full+reply | yes | 7147 | 19 | 2 | - | 3051 B | 6324 | 6840 | 890 | 20 | buffered |  |
| 5x16 | anonymous hidden | full+2tree | yes | 5728 | 20 | 2 | - | 1632 B | 4872 | 5389 | 923 | 21 | buffered |  |
| 5x16 | anonymous public owners | min | yes | 5192 | 13 | 1 | - | 1096 B | 4644 | 5161 | 615 | 14 | buffered |  |
| 5x16 | anonymous public owners | full | yes | 5819 | 23 | 3 | none | 1723 B | 4803 | 5288 | 1083 | 24 | buffered |  |
| 5x16 | anonymous public owners | full+spl | yes | 6187 | 30 | 3 | - | 2091 B | 4935 | 5292 | 1319 | 31 | buffered |  |
| 5x16 | anonymous public owners | full+data | yes | 7405 | 23 | 3 | - | 3309 B | 6389 | 6842 | 1083 | 24 | buffered |  |
| 5x16 | anonymous public owners | full+reply | yes | 7276 | 23 | 3 | - | 3180 B | 6260 | 6743 | 1083 | 24 | buffered |  |
| 5x16 | anonymous public owners | full+2tree | yes | 5857 | 24 | 3 | - | 1761 B | 4808 | 5292 | 1116 | 25 | buffered |  |
| 5x16 | confidential entry | min | none | 5648 | 13 | 1 | - | 1552 B | 5100 | 5619 | 615 | 14 | buffered |  |
| 5x16 | confidential entry | full | none | 6203 | 23 | 3 | none | 2107 B | 5187 | 5664 | 1083 | 24 | buffered |  |
| 5x16 | confidential entry | full+spl | none | 6571 | 30 | 3 | - | 2475 B | 5319 | 5668 | 1319 | 31 | buffered |  |
| 5x16 | confidential entry | full+data | none | 7789 | 23 | 3 | - | 3693 B | 6773 | 7218 | 1083 | 24 | buffered |  |
| 5x16 | confidential entry | full+reply | none | 6203 | 23 | 3 | - | 2107 B | 5187 | 5664 | 1083 | 24 | buffered |  |
| 5x16 | confidential entry | full+2tree | none | 6241 | 24 | 3 | - | 2145 B | 5192 | 5668 | 1116 | 25 | buffered |  |
| 5x16 | anonymous entry | min | none | 6295 | 13 | 1 | - | 2199 B | 5748 | 6266 | 614 | 14 | buffered |  |
| 5x16 | anonymous entry | full | none | 6730 | 19 | 2 | none | 2634 B | 5907 | 6393 | 890 | 20 | buffered |  |
| 5x16 | anonymous entry | full+spl | none | 7098 | 26 | 2 | - | 3002 B | 6039 | 6397 | 1126 | 27 | buffered |  |
| 5x16 | anonymous entry | full+data | none | 8316 | 19 | 2 | - | 4220 B | 7493 | 7947 | 890 | 20 | buffered |  |
| 5x16 | anonymous entry | full+reply | none | 8187 | 19 | 2 | - | 4091 B | 7364 | 7848 | 890 | 20 | buffered |  |
| 5x16 | anonymous entry | full+2tree | none | 6768 | 20 | 2 | - | 2672 B | 5912 | 6397 | 923 | 21 | buffered |  |
| 5x16 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 5x16 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 6x8 | confidential signer | min | yes | 2967 | 14 | 1 | - |  | 2386 | 2620 | 648 | 15 | inline |  |
| 6x8 | confidential signer | full | yes | 3522 | 24 | 3 | 6 |  | 2473 | 2665 | 1116 | 25 | inline |  |
| 6x8 | confidential signer | full+spl | yes | 3890 | 31 | 3 | - |  | 2605 | 2669 | 1352 | 32 | inline |  |
| 6x8 | confidential signer | full+data | yes | 4316 | 24 | 3 | - | 220 B | 3267 | 3443 | 1116 | 25 | buffered |  |
| 6x8 | confidential signer | full+reply | yes | 3522 | 24 | 3 | - |  | 2473 | 2665 | 1116 | 25 | inline |  |
| 6x8 | confidential signer | full+2tree | yes | 3560 | 25 | 3 | - |  | 2478 | 2669 | 1149 | 26 | inline |  |
| 6x8 | confidential in-proof | min | yes | 3062 | 14 | 1 | - |  | 2482 | 2717 | 647 | 15 | inline |  |
| 6x8 | confidential in-proof | full | yes | 3521 | 23 | 2 | 5 |  | 2569 | 2762 | 1019 | 24 | inline |  |
| 6x8 | confidential in-proof | full+spl | yes | 3889 | 30 | 2 | - |  | 2701 | 2766 | 1255 | 31 | inline |  |
| 6x8 | confidential in-proof | full+data | yes | 4315 | 23 | 2 | - | 219 B | 3363 | 3540 | 1019 | 24 | buffered |  |
| 6x8 | confidential in-proof | full+reply | yes | 3521 | 23 | 2 | - |  | 2569 | 2762 | 1019 | 24 | inline |  |
| 6x8 | confidential in-proof | full+2tree | yes | 3559 | 24 | 2 | - |  | 2574 | 2766 | 1052 | 25 | inline |  |
| 6x8 | anonymous hidden | min | yes | 3326 | 14 | 1 | - |  | 2746 | 3011 | 647 | 15 | inline |  |
| 6x8 | anonymous hidden | full | yes | 3761 | 20 | 2 | 3 |  | 2905 | 3138 | 923 | 21 | inline |  |
| 6x8 | anonymous hidden | full+spl | yes | 4129 | 27 | 2 | - | 33 B | 3037 | 3142 | 1159 | 28 | buffered |  |
| 6x8 | anonymous hidden | full+data | yes | 4555 | 20 | 2 | - | 459 B | 3699 | 3916 | 923 | 21 | buffered |  |
| 6x8 | anonymous hidden | full+reply | yes | 4442 | 20 | 2 | - | 346 B | 3586 | 3817 | 923 | 21 | buffered |  |
| 6x8 | anonymous hidden | full+2tree | yes | 3799 | 21 | 2 | - |  | 2910 | 3142 | 956 | 22 | inline |  |
| 6x8 | anonymous public owners | min | yes | 3263 | 14 | 1 | - |  | 2682 | 2914 | 648 | 15 | inline |  |
| 6x8 | anonymous public owners | full | yes | 3890 | 24 | 3 | 3 |  | 2841 | 3041 | 1116 | 25 | inline |  |
| 6x8 | anonymous public owners | full+spl | yes | 4258 | 31 | 3 | - | 162 B | 2973 | 3045 | 1352 | 32 | buffered |  |
| 6x8 | anonymous public owners | full+data | yes | 4684 | 24 | 3 | - | 588 B | 3635 | 3819 | 1116 | 25 | buffered |  |
| 6x8 | anonymous public owners | full+reply | yes | 4571 | 24 | 3 | - | 475 B | 3522 | 3720 | 1116 | 25 | buffered |  |
| 6x8 | anonymous public owners | full+2tree | yes | 3928 | 25 | 3 | - |  | 2846 | 3045 | 1149 | 26 | inline |  |
| 6x8 | confidential entry | min | none | 4175 | 14 | 1 | - | 79 B | 3594 | 3828 | 648 | 15 | buffered |  |
| 6x8 | confidential entry | full | none | 4730 | 24 | 3 | none | 634 B | 3681 | 3873 | 1116 | 25 | buffered |  |
| 6x8 | confidential entry | full+spl | none | 5098 | 31 | 3 | - | 1002 B | 3813 | 3877 | 1352 | 32 | buffered |  |
| 6x8 | confidential entry | full+data | none | 5524 | 24 | 3 | - | 1428 B | 4475 | 4651 | 1116 | 25 | buffered |  |
| 6x8 | confidential entry | full+reply | none | 4730 | 24 | 3 | - | 634 B | 3681 | 3873 | 1116 | 25 | buffered |  |
| 6x8 | confidential entry | full+2tree | none | 4768 | 25 | 3 | - | 672 B | 3686 | 3877 | 1149 | 26 | buffered |  |
| 6x8 | anonymous entry | min | none | 4566 | 14 | 1 | - | 470 B | 3986 | 4219 | 647 | 15 | buffered |  |
| 6x8 | anonymous entry | full | none | 5001 | 20 | 2 | none | 905 B | 4145 | 4346 | 923 | 21 | buffered |  |
| 6x8 | anonymous entry | full+spl | none | 5369 | 27 | 2 | - | 1273 B | 4277 | 4350 | 1159 | 28 | buffered |  |
| 6x8 | anonymous entry | full+data | none | 5795 | 20 | 2 | - | 1699 B | 4939 | 5124 | 923 | 21 | buffered |  |
| 6x8 | anonymous entry | full+reply | none | 5682 | 20 | 2 | - | 1586 B | 4826 | 5025 | 923 | 21 | buffered |  |
| 6x8 | anonymous entry | full+2tree | none | 5039 | 21 | 2 | - | 943 B | 4150 | 4350 | 956 | 22 | buffered |  |
| 6x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 6x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x2 | confidential signer | min | yes | 1795 | 16 | 1 | - |  | 1148 | 1168 | 714 | 17 | inline |  |
| 8x2 | confidential signer | full | yes | 2350 | 26 | 3 | 8 |  | 1235 | 1213 | 1182 | 27 | inline |  |
| 8x2 | confidential signer | full+spl | yes | 2718 | 33 | 3 | - |  | 1367 | 1217 | 1418 | 34 | inline |  |
| 8x2 | confidential signer | full+data | yes | 2550 | 26 | 3 | - |  | 1435 | 1409 | 1182 | 27 | inline |  |
| 8x2 | confidential signer | full+reply | yes | 2350 | 26 | 3 | - |  | 1235 | 1213 | 1182 | 27 | inline |  |
| 8x2 | confidential signer | full+2tree | yes | 2388 | 27 | 3 | - |  | 1240 | 1217 | 1215 | 28 | inline |  |
| 8x2 | confidential in-proof | min | yes | 1890 | 16 | 1 | - |  | 1244 | 1265 | 713 | 17 | inline |  |
| 8x2 | confidential in-proof | full | yes | 2349 | 25 | 2 | 8 |  | 1331 | 1310 | 1085 | 26 | inline |  |
| 8x2 | confidential in-proof | full+spl | yes | 2717 | 32 | 2 | - |  | 1463 | 1314 | 1321 | 33 | inline |  |
| 8x2 | confidential in-proof | full+data | yes | 2549 | 25 | 2 | - |  | 1531 | 1506 | 1085 | 26 | inline |  |
| 8x2 | confidential in-proof | full+reply | yes | 2349 | 25 | 2 | - |  | 1331 | 1310 | 1085 | 26 | inline |  |
| 8x2 | confidential in-proof | full+2tree | yes | 2387 | 26 | 2 | - |  | 1336 | 1314 | 1118 | 27 | inline |  |
| 8x2 | anonymous hidden | min | yes | 1962 | 16 | 1 | - |  | 1316 | 1367 | 713 | 17 | inline |  |
| 8x2 | anonymous hidden | full | yes | 2397 | 22 | 2 | 8 |  | 1475 | 1494 | 989 | 23 | inline |  |
| 8x2 | anonymous hidden | full+spl | yes | 2765 | 29 | 2 | - |  | 1607 | 1498 | 1225 | 30 | inline |  |
| 8x2 | anonymous hidden | full+data | yes | 2597 | 22 | 2 | - |  | 1675 | 1690 | 989 | 23 | inline |  |
| 8x2 | anonymous hidden | full+reply | yes | 2496 | 22 | 2 | - |  | 1574 | 1591 | 989 | 23 | inline |  |
| 8x2 | anonymous hidden | full+2tree | yes | 2435 | 23 | 2 | - |  | 1480 | 1498 | 1022 | 24 | inline |  |
| 8x2 | anonymous public owners | min | yes | 1899 | 16 | 1 | - |  | 1252 | 1270 | 714 | 17 | inline |  |
| 8x2 | anonymous public owners | full | yes | 2526 | 26 | 3 | 8 |  | 1411 | 1397 | 1182 | 27 | inline |  |
| 8x2 | anonymous public owners | full+spl | yes | 2894 | 33 | 3 | - |  | 1543 | 1401 | 1418 | 34 | inline |  |
| 8x2 | anonymous public owners | full+data | yes | 2726 | 26 | 3 | - |  | 1611 | 1593 | 1182 | 27 | inline |  |
| 8x2 | anonymous public owners | full+reply | yes | 2625 | 26 | 3 | - |  | 1510 | 1494 | 1182 | 27 | inline |  |
| 8x2 | anonymous public owners | full+2tree | yes | 2564 | 27 | 3 | - |  | 1416 | 1401 | 1215 | 28 | inline |  |
| 8x2 | confidential entry | min | yes | 3403 | 16 | 1 | - |  | 2756 | 2776 | 714 | 17 | inline |  |
| 8x2 | confidential entry | full | yes | 3958 | 26 | 3 | 2 |  | 2843 | 2821 | 1182 | 27 | inline |  |
| 8x2 | confidential entry | full+spl | yes | 4326 | 33 | 3 | - | 230 B | 2975 | 2825 | 1418 | 34 | buffered |  |
| 8x2 | confidential entry | full+data | yes | 4158 | 26 | 3 | - | 62 B | 3043 | 3017 | 1182 | 27 | buffered |  |
| 8x2 | confidential entry | full+reply | yes | 3958 | 26 | 3 | - |  | 2843 | 2821 | 1182 | 27 | inline |  |
| 8x2 | confidential entry | full+2tree | yes | 3996 | 27 | 3 | - |  | 2848 | 2825 | 1215 | 28 | inline |  |
| 8x2 | anonymous entry | min | yes | 3602 | 16 | 1 | - |  | 2956 | 2975 | 713 | 17 | inline |  |
| 8x2 | anonymous entry | full | yes | 4037 | 22 | 2 | 0 |  | 3115 | 3102 | 989 | 23 | inline |  |
| 8x2 | anonymous entry | full+spl | yes | 4405 | 29 | 2 | - | 309 B | 3247 | 3106 | 1225 | 30 | buffered |  |
| 8x2 | anonymous entry | full+data | yes | 4237 | 22 | 2 | - | 141 B | 3315 | 3298 | 989 | 23 | buffered |  |
| 8x2 | anonymous entry | full+reply | yes | 4136 | 22 | 2 | - | 40 B | 3214 | 3199 | 989 | 23 | buffered |  |
| 8x2 | anonymous entry | full+2tree | yes | 4075 | 23 | 2 | - |  | 3120 | 3106 | 1022 | 24 | inline |  |
| 8x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x4 | confidential signer | min | yes | 2229 | 16 | 1 | - |  | 1582 | 1674 | 714 | 17 | inline |  |
| 8x4 | confidential signer | full | yes | 2784 | 26 | 3 | 8 |  | 1669 | 1719 | 1182 | 27 | inline |  |
| 8x4 | confidential signer | full+spl | yes | 3152 | 33 | 3 | - |  | 1801 | 1723 | 1418 | 34 | inline |  |
| 8x4 | confidential signer | full+data | yes | 3182 | 26 | 3 | - |  | 2067 | 2109 | 1182 | 27 | inline |  |
| 8x4 | confidential signer | full+reply | yes | 2784 | 26 | 3 | - |  | 1669 | 1719 | 1182 | 27 | inline |  |
| 8x4 | confidential signer | full+2tree | yes | 2822 | 27 | 3 | - |  | 1674 | 1723 | 1215 | 28 | inline |  |
| 8x4 | confidential in-proof | min | yes | 2324 | 16 | 1 | - |  | 1678 | 1771 | 713 | 17 | inline |  |
| 8x4 | confidential in-proof | full | yes | 2783 | 25 | 2 | 8 |  | 1765 | 1816 | 1085 | 26 | inline |  |
| 8x4 | confidential in-proof | full+spl | yes | 3151 | 32 | 2 | - |  | 1897 | 1820 | 1321 | 33 | inline |  |
| 8x4 | confidential in-proof | full+data | yes | 3181 | 25 | 2 | - |  | 2163 | 2206 | 1085 | 26 | inline |  |
| 8x4 | confidential in-proof | full+reply | yes | 2783 | 25 | 2 | - |  | 1765 | 1816 | 1085 | 26 | inline |  |
| 8x4 | confidential in-proof | full+2tree | yes | 2821 | 26 | 2 | - |  | 1770 | 1820 | 1118 | 27 | inline |  |
| 8x4 | anonymous hidden | min | yes | 2460 | 16 | 1 | - |  | 1814 | 1937 | 713 | 17 | inline |  |
| 8x4 | anonymous hidden | full | yes | 2895 | 22 | 2 | 8 |  | 1973 | 2064 | 989 | 23 | inline |  |
| 8x4 | anonymous hidden | full+spl | yes | 3263 | 29 | 2 | - |  | 2105 | 2068 | 1225 | 30 | inline |  |
| 8x4 | anonymous hidden | full+data | yes | 3293 | 22 | 2 | - |  | 2371 | 2454 | 989 | 23 | inline |  |
| 8x4 | anonymous hidden | full+reply | yes | 3188 | 22 | 2 | - |  | 2266 | 2355 | 989 | 23 | inline |  |
| 8x4 | anonymous hidden | full+2tree | yes | 2933 | 23 | 2 | - |  | 1978 | 2068 | 1022 | 24 | inline |  |
| 8x4 | anonymous public owners | min | yes | 2397 | 16 | 1 | - |  | 1750 | 1840 | 714 | 17 | inline |  |
| 8x4 | anonymous public owners | full | yes | 3024 | 26 | 3 | 8 |  | 1909 | 1967 | 1182 | 27 | inline |  |
| 8x4 | anonymous public owners | full+spl | yes | 3392 | 33 | 3 | - |  | 2041 | 1971 | 1418 | 34 | inline |  |
| 8x4 | anonymous public owners | full+data | yes | 3422 | 26 | 3 | - |  | 2307 | 2357 | 1182 | 27 | inline |  |
| 8x4 | anonymous public owners | full+reply | yes | 3317 | 26 | 3 | - |  | 2202 | 2258 | 1182 | 27 | inline |  |
| 8x4 | anonymous public owners | full+2tree | yes | 3062 | 27 | 3 | - |  | 1914 | 1971 | 1215 | 28 | inline |  |
| 8x4 | confidential entry | min | yes | 3837 | 16 | 1 | - |  | 3190 | 3282 | 714 | 17 | inline |  |
| 8x4 | confidential entry | full | yes | 4392 | 26 | 3 | none | 296 B | 3277 | 3327 | 1182 | 27 | buffered |  |
| 8x4 | confidential entry | full+spl | yes | 4760 | 33 | 3 | - | 664 B | 3409 | 3331 | 1418 | 34 | buffered |  |
| 8x4 | confidential entry | full+data | yes | 4790 | 26 | 3 | - | 694 B | 3675 | 3717 | 1182 | 27 | buffered |  |
| 8x4 | confidential entry | full+reply | yes | 4392 | 26 | 3 | - | 296 B | 3277 | 3327 | 1182 | 27 | buffered |  |
| 8x4 | confidential entry | full+2tree | yes | 4430 | 27 | 3 | - | 334 B | 3282 | 3331 | 1215 | 28 | buffered |  |
| 8x4 | anonymous entry | min | yes | 4100 | 16 | 1 | - | 4 B | 3454 | 3545 | 713 | 17 | buffered |  |
| 8x4 | anonymous entry | full | yes | 4535 | 22 | 2 | none | 439 B | 3613 | 3672 | 989 | 23 | buffered |  |
| 8x4 | anonymous entry | full+spl | yes | 4903 | 29 | 2 | - | 807 B | 3745 | 3676 | 1225 | 30 | buffered |  |
| 8x4 | anonymous entry | full+data | yes | 4933 | 22 | 2 | - | 837 B | 4011 | 4062 | 989 | 23 | buffered |  |
| 8x4 | anonymous entry | full+reply | yes | 4828 | 22 | 2 | - | 732 B | 3906 | 3963 | 989 | 23 | buffered |  |
| 8x4 | anonymous entry | full+2tree | yes | 4573 | 23 | 2 | - | 477 B | 3618 | 3676 | 1022 | 24 | buffered |  |
| 8x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x8 | confidential signer | min | yes | 3097 | 16 | 1 | - |  | 2450 | 2686 | 714 | 17 | inline |  |
| 8x8 | confidential signer | full | yes | 3652 | 26 | 3 | 5 |  | 2537 | 2731 | 1182 | 27 | inline |  |
| 8x8 | confidential signer | full+spl | yes | 4020 | 33 | 3 | - |  | 2669 | 2735 | 1418 | 34 | inline |  |
| 8x8 | confidential signer | full+data | yes | 4446 | 26 | 3 | - | 350 B | 3331 | 3509 | 1182 | 27 | buffered |  |
| 8x8 | confidential signer | full+reply | yes | 3652 | 26 | 3 | - |  | 2537 | 2731 | 1182 | 27 | inline |  |
| 8x8 | confidential signer | full+2tree | yes | 3690 | 27 | 3 | - |  | 2542 | 2735 | 1215 | 28 | inline |  |
| 8x8 | confidential in-proof | min | yes | 3192 | 16 | 1 | - |  | 2546 | 2783 | 713 | 17 | inline |  |
| 8x8 | confidential in-proof | full | yes | 3651 | 25 | 2 | 4 |  | 2633 | 2828 | 1085 | 26 | inline |  |
| 8x8 | confidential in-proof | full+spl | yes | 4019 | 32 | 2 | - |  | 2765 | 2832 | 1321 | 33 | inline |  |
| 8x8 | confidential in-proof | full+data | yes | 4445 | 25 | 2 | - | 349 B | 3427 | 3606 | 1085 | 26 | buffered |  |
| 8x8 | confidential in-proof | full+reply | yes | 3651 | 25 | 2 | - |  | 2633 | 2828 | 1085 | 26 | inline |  |
| 8x8 | confidential in-proof | full+2tree | yes | 3689 | 26 | 2 | - |  | 2638 | 2832 | 1118 | 27 | inline |  |
| 8x8 | anonymous hidden | min | yes | 3456 | 16 | 1 | - |  | 2810 | 3077 | 713 | 17 | inline |  |
| 8x8 | anonymous hidden | full | yes | 3891 | 22 | 2 | 2 |  | 2969 | 3204 | 989 | 23 | inline |  |
| 8x8 | anonymous hidden | full+spl | yes | 4259 | 29 | 2 | - | 163 B | 3101 | 3208 | 1225 | 30 | buffered |  |
| 8x8 | anonymous hidden | full+data | yes | 4685 | 22 | 2 | - | 589 B | 3763 | 3982 | 989 | 23 | buffered |  |
| 8x8 | anonymous hidden | full+reply | yes | 4572 | 22 | 2 | - | 476 B | 3650 | 3883 | 989 | 23 | buffered |  |
| 8x8 | anonymous hidden | full+2tree | yes | 3929 | 23 | 2 | - |  | 2974 | 3208 | 1022 | 24 | inline |  |
| 8x8 | anonymous public owners | min | yes | 3393 | 16 | 1 | - |  | 2746 | 2980 | 714 | 17 | inline |  |
| 8x8 | anonymous public owners | full | yes | 4020 | 26 | 3 | 1 |  | 2905 | 3107 | 1182 | 27 | inline |  |
| 8x8 | anonymous public owners | full+spl | yes | 4388 | 33 | 3 | - | 292 B | 3037 | 3111 | 1418 | 34 | buffered |  |
| 8x8 | anonymous public owners | full+data | yes | 4814 | 26 | 3 | - | 718 B | 3699 | 3885 | 1182 | 27 | buffered |  |
| 8x8 | anonymous public owners | full+reply | yes | 4701 | 26 | 3 | - | 605 B | 3586 | 3786 | 1182 | 27 | buffered |  |
| 8x8 | anonymous public owners | full+2tree | yes | 4058 | 27 | 3 | - |  | 2910 | 3111 | 1215 | 28 | inline |  |
| 8x8 | confidential entry | min | none | 4705 | 16 | 1 | - | 609 B | 4058 | 4294 | 714 | 17 | buffered |  |
| 8x8 | confidential entry | full | none | 5260 | 26 | 3 | none | 1164 B | 4145 | 4339 | 1182 | 27 | buffered |  |
| 8x8 | confidential entry | full+spl | none | 5628 | 33 | 3 | - | 1532 B | 4277 | 4343 | 1418 | 34 | buffered |  |
| 8x8 | confidential entry | full+data | none | 6054 | 26 | 3 | - | 1958 B | 4939 | 5117 | 1182 | 27 | buffered |  |
| 8x8 | confidential entry | full+reply | none | 5260 | 26 | 3 | - | 1164 B | 4145 | 4339 | 1182 | 27 | buffered |  |
| 8x8 | confidential entry | full+2tree | none | 5298 | 27 | 3 | - | 1202 B | 4150 | 4343 | 1215 | 28 | buffered |  |
| 8x8 | anonymous entry | min | none | 5096 | 16 | 1 | - | 1000 B | 4450 | 4685 | 713 | 17 | buffered |  |
| 8x8 | anonymous entry | full | none | 5531 | 22 | 2 | none | 1435 B | 4609 | 4812 | 989 | 23 | buffered |  |
| 8x8 | anonymous entry | full+spl | none | 5899 | 29 | 2 | - | 1803 B | 4741 | 4816 | 1225 | 30 | buffered |  |
| 8x8 | anonymous entry | full+data | none | 6325 | 22 | 2 | - | 2229 B | 5403 | 5590 | 989 | 23 | buffered |  |
| 8x8 | anonymous entry | full+reply | none | 6212 | 22 | 2 | - | 2116 B | 5290 | 5491 | 989 | 23 | buffered |  |
| 8x8 | anonymous entry | full+2tree | none | 5569 | 23 | 2 | - | 1473 B | 4614 | 4816 | 1022 | 24 | buffered |  |
| 8x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x16 | confidential signer | min | none | 4835 | 16 | 1 | - | 739 B | 4188 | 4710 | 714 | 17 | buffered |  |
| 8x16 | confidential signer | full | none | 5390 | 26 | 3 | none | 1294 B | 4275 | 4755 | 1182 | 27 | buffered |  |
| 8x16 | confidential signer | full+spl | none | 5758 | 33 | 3 | - | 1662 B | 4407 | 4759 | 1418 | 34 | buffered |  |
| 8x16 | confidential signer | full+data | none | 6976 | 26 | 3 | - | 2880 B | 5861 | 6309 | 1182 | 27 | buffered |  |
| 8x16 | confidential signer | full+reply | none | 5390 | 26 | 3 | - | 1294 B | 4275 | 4755 | 1182 | 27 | buffered |  |
| 8x16 | confidential signer | full+2tree | none | 5428 | 27 | 3 | - | 1332 B | 4280 | 4759 | 1215 | 28 | buffered |  |
| 8x16 | confidential in-proof | min | none | 4930 | 16 | 1 | - | 834 B | 4284 | 4807 | 713 | 17 | buffered |  |
| 8x16 | confidential in-proof | full | none | 5389 | 25 | 2 | none | 1293 B | 4371 | 4852 | 1085 | 26 | buffered |  |
| 8x16 | confidential in-proof | full+spl | none | 5757 | 32 | 2 | - | 1661 B | 4503 | 4856 | 1321 | 33 | buffered |  |
| 8x16 | confidential in-proof | full+data | none | 6975 | 25 | 2 | - | 2879 B | 5957 | 6406 | 1085 | 26 | buffered |  |
| 8x16 | confidential in-proof | full+reply | none | 5389 | 25 | 2 | - | 1293 B | 4371 | 4852 | 1085 | 26 | buffered |  |
| 8x16 | confidential in-proof | full+2tree | none | 5427 | 26 | 2 | - | 1331 B | 4376 | 4856 | 1118 | 27 | buffered |  |
| 8x16 | anonymous hidden | min | none | 5450 | 16 | 1 | - | 1354 B | 4804 | 5357 | 713 | 17 | buffered |  |
| 8x16 | anonymous hidden | full | none | 5885 | 22 | 2 | none | 1789 B | 4963 | 5484 | 989 | 23 | buffered |  |
| 8x16 | anonymous hidden | full+spl | none | 6253 | 29 | 2 | - | 2157 B | 5095 | 5488 | 1225 | 30 | buffered |  |
| 8x16 | anonymous hidden | full+data | none | 7471 | 22 | 2 | - | 3375 B | 6549 | 7038 | 989 | 23 | buffered |  |
| 8x16 | anonymous hidden | full+reply | none | 7342 | 22 | 2 | - | 3246 B | 6420 | 6939 | 989 | 23 | buffered |  |
| 8x16 | anonymous hidden | full+2tree | none | 5923 | 23 | 2 | - | 1827 B | 4968 | 5488 | 1022 | 24 | buffered |  |
| 8x16 | anonymous public owners | min | none | 5387 | 16 | 1 | - | 1291 B | 4740 | 5260 | 714 | 17 | buffered |  |
| 8x16 | anonymous public owners | full | none | 6014 | 26 | 3 | none | 1918 B | 4899 | 5387 | 1182 | 27 | buffered |  |
| 8x16 | anonymous public owners | full+spl | none | 6382 | 33 | 3 | - | 2286 B | 5031 | 5391 | 1418 | 34 | buffered |  |
| 8x16 | anonymous public owners | full+data | none | 7600 | 26 | 3 | - | 3504 B | 6485 | 6941 | 1182 | 27 | buffered |  |
| 8x16 | anonymous public owners | full+reply | none | 7471 | 26 | 3 | - | 3375 B | 6356 | 6842 | 1182 | 27 | buffered |  |
| 8x16 | anonymous public owners | full+2tree | none | 6052 | 27 | 3 | - | 1956 B | 4904 | 5391 | 1215 | 28 | buffered |  |
| 8x16 | confidential entry | min | none | 6443 | 16 | 1 | - | 2347 B | 5796 | 6318 | 714 | 17 | buffered |  |
| 8x16 | confidential entry | full | none | 6998 | 26 | 3 | none | 2902 B | 5883 | 6363 | 1182 | 27 | buffered |  |
| 8x16 | confidential entry | full+spl | none | 7366 | 33 | 3 | - | 3270 B | 6015 | 6367 | 1418 | 34 | buffered |  |
| 8x16 | confidential entry | full+data | none | 8584 | 26 | 3 | - | 4488 B | 7469 | 7917 | 1182 | 27 | buffered |  |
| 8x16 | confidential entry | full+reply | none | 6998 | 26 | 3 | - | 2902 B | 5883 | 6363 | 1182 | 27 | buffered |  |
| 8x16 | confidential entry | full+2tree | none | 7036 | 27 | 3 | - | 2940 B | 5888 | 6367 | 1215 | 28 | buffered |  |
| 8x16 | anonymous entry | min | none | 7090 | 16 | 1 | - | 2994 B | 6444 | 6965 | 713 | 17 | buffered |  |
| 8x16 | anonymous entry | full | none | 7525 | 22 | 2 | none | 3429 B | 6603 | 7092 | 989 | 23 | buffered |  |
| 8x16 | anonymous entry | full+spl | none | 7893 | 29 | 2 | - | 3797 B | 6735 | 7096 | 1225 | 30 | buffered |  |
| 8x16 | anonymous entry | full+data | none | 9111 | 22 | 2 | - | 5015 B | 8189 | 8646 | 989 | 23 | buffered |  |
| 8x16 | anonymous entry | full+reply | none | 8982 | 22 | 2 | - | 4886 B | 8060 | 8547 | 989 | 23 | buffered |  |
| 8x16 | anonymous entry | full+2tree | none | 7563 | 23 | 2 | - | 3467 B | 6608 | 7096 | 1022 | 24 | buffered |  |
| 8x16 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x16 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 12x2 | confidential signer | min | yes | 2055 | 20 | 1 | - |  | 1276 | 1300 | 846 | 21 | inline |  |
| 12x2 | confidential signer | full | yes | 2610 | 30 | 3 | 10 |  | 1363 | 1345 | 1314 | 31 | inline |  |
| 12x2 | confidential signer | full+spl | yes | 2978 | 37 | 3 | - |  | 1495 | 1349 | 1550 | 38 | inline |  |
| 12x2 | confidential signer | full+data | yes | 2810 | 30 | 3 | - |  | 1563 | 1541 | 1314 | 31 | inline |  |
| 12x2 | confidential signer | full+reply | yes | 2610 | 30 | 3 | - |  | 1363 | 1345 | 1314 | 31 | inline |  |
| 12x2 | confidential signer | full+2tree | yes | 2649 | 31 | 3 | - |  | 1369 | 1349 | 1347 | 32 | inline |  |
| 12x2 | confidential in-proof | min | yes | 2150 | 20 | 1 | - |  | 1372 | 1397 | 845 | 21 | inline |  |
| 12x2 | confidential in-proof | full | yes | 2609 | 29 | 2 | 10 |  | 1459 | 1442 | 1217 | 30 | inline |  |
| 12x2 | confidential in-proof | full+spl | yes | 2977 | 36 | 2 | - |  | 1591 | 1446 | 1453 | 37 | inline |  |
| 12x2 | confidential in-proof | full+data | yes | 2809 | 29 | 2 | - |  | 1659 | 1638 | 1217 | 30 | inline |  |
| 12x2 | confidential in-proof | full+reply | yes | 2609 | 29 | 2 | - |  | 1459 | 1442 | 1217 | 30 | inline |  |
| 12x2 | confidential in-proof | full+2tree | yes | 2648 | 30 | 2 | - |  | 1465 | 1446 | 1250 | 31 | inline |  |
| 12x2 | anonymous hidden | min | yes | 2222 | 20 | 1 | - |  | 1444 | 1499 | 845 | 21 | inline |  |
| 12x2 | anonymous hidden | full | yes | 2657 | 26 | 2 | 10 |  | 1603 | 1626 | 1121 | 27 | inline |  |
| 12x2 | anonymous hidden | full+spl | yes | 3025 | 33 | 2 | - |  | 1735 | 1630 | 1357 | 34 | inline |  |
| 12x2 | anonymous hidden | full+data | yes | 2857 | 26 | 2 | - |  | 1803 | 1822 | 1121 | 27 | inline |  |
| 12x2 | anonymous hidden | full+reply | yes | 2756 | 26 | 2 | - |  | 1702 | 1723 | 1121 | 27 | inline |  |
| 12x2 | anonymous hidden | full+2tree | yes | 2696 | 27 | 2 | - |  | 1609 | 1630 | 1154 | 28 | inline |  |
| 12x2 | anonymous public owners | min | yes | 2159 | 20 | 1 | - |  | 1380 | 1402 | 846 | 21 | inline |  |
| 12x2 | anonymous public owners | full | yes | 2786 | 30 | 3 | 10 |  | 1539 | 1529 | 1314 | 31 | inline |  |
| 12x2 | anonymous public owners | full+spl | yes | 3154 | 37 | 3 | - |  | 1671 | 1533 | 1550 | 38 | inline |  |
| 12x2 | anonymous public owners | full+data | yes | 2986 | 30 | 3 | - |  | 1739 | 1725 | 1314 | 31 | inline |  |
| 12x2 | anonymous public owners | full+reply | yes | 2885 | 30 | 3 | - |  | 1638 | 1626 | 1314 | 31 | inline |  |
| 12x2 | anonymous public owners | full+2tree | yes | 2825 | 31 | 3 | - |  | 1545 | 1533 | 1347 | 32 | inline |  |
| 12x2 | confidential entry | min | none | 4463 | 20 | 1 | - | 367 B | 3684 | 3708 | 846 | 21 | buffered |  |
| 12x2 | confidential entry | full | none | 5018 | 30 | 3 | none | 922 B | 3771 | 3753 | 1314 | 31 | buffered |  |
| 12x2 | confidential entry | full+spl | none | 5386 | 37 | 3 | - | 1290 B | 3903 | 3757 | 1550 | 38 | buffered |  |
| 12x2 | confidential entry | full+data | none | 5218 | 30 | 3 | - | 1122 B | 3971 | 3949 | 1314 | 31 | buffered |  |
| 12x2 | confidential entry | full+reply | none | 5018 | 30 | 3 | - | 922 B | 3771 | 3753 | 1314 | 31 | buffered |  |
| 12x2 | confidential entry | full+2tree | none | 5057 | 31 | 3 | - | 961 B | 3777 | 3757 | 1347 | 32 | buffered |  |
| 12x2 | anonymous entry | min | none | 4662 | 20 | 1 | - | 566 B | 3884 | 3907 | 845 | 21 | buffered |  |
| 12x2 | anonymous entry | full | none | 5097 | 26 | 2 | none | 1001 B | 4043 | 4034 | 1121 | 27 | buffered |  |
| 12x2 | anonymous entry | full+spl | none | 5465 | 33 | 2 | - | 1369 B | 4175 | 4038 | 1357 | 34 | buffered |  |
| 12x2 | anonymous entry | full+data | none | 5297 | 26 | 2 | - | 1201 B | 4243 | 4230 | 1121 | 27 | buffered |  |
| 12x2 | anonymous entry | full+reply | none | 5196 | 26 | 2 | - | 1100 B | 4142 | 4131 | 1121 | 27 | buffered |  |
| 12x2 | anonymous entry | full+2tree | none | 5136 | 27 | 2 | - | 1040 B | 4049 | 4038 | 1154 | 28 | buffered |  |
| 12x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 12x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 12x4 | confidential signer | min | yes | 2489 | 20 | 1 | - |  | 1710 | 1806 | 846 | 21 | inline |  |
| 12x4 | confidential signer | full | yes | 3044 | 30 | 3 | 10 |  | 1797 | 1851 | 1314 | 31 | inline |  |
| 12x4 | confidential signer | full+spl | yes | 3412 | 37 | 3 | - |  | 1929 | 1855 | 1550 | 38 | inline |  |
| 12x4 | confidential signer | full+data | yes | 3442 | 30 | 3 | - |  | 2195 | 2241 | 1314 | 31 | inline |  |
| 12x4 | confidential signer | full+reply | yes | 3044 | 30 | 3 | - |  | 1797 | 1851 | 1314 | 31 | inline |  |
| 12x4 | confidential signer | full+2tree | yes | 3083 | 31 | 3 | - |  | 1803 | 1855 | 1347 | 32 | inline |  |
| 12x4 | confidential in-proof | min | yes | 2584 | 20 | 1 | - |  | 1806 | 1903 | 845 | 21 | inline |  |
| 12x4 | confidential in-proof | full | yes | 3043 | 29 | 2 | 10 |  | 1893 | 1948 | 1217 | 30 | inline |  |
| 12x4 | confidential in-proof | full+spl | yes | 3411 | 36 | 2 | - |  | 2025 | 1952 | 1453 | 37 | inline |  |
| 12x4 | confidential in-proof | full+data | yes | 3441 | 29 | 2 | - |  | 2291 | 2338 | 1217 | 30 | inline |  |
| 12x4 | confidential in-proof | full+reply | yes | 3043 | 29 | 2 | - |  | 1893 | 1948 | 1217 | 30 | inline |  |
| 12x4 | confidential in-proof | full+2tree | yes | 3082 | 30 | 2 | - |  | 1899 | 1952 | 1250 | 31 | inline |  |
| 12x4 | anonymous hidden | min | yes | 2720 | 20 | 1 | - |  | 1942 | 2069 | 845 | 21 | inline |  |
| 12x4 | anonymous hidden | full | yes | 3155 | 26 | 2 | 9 |  | 2101 | 2196 | 1121 | 27 | inline |  |
| 12x4 | anonymous hidden | full+spl | yes | 3523 | 33 | 2 | - |  | 2233 | 2200 | 1357 | 34 | inline |  |
| 12x4 | anonymous hidden | full+data | yes | 3553 | 26 | 2 | - |  | 2499 | 2586 | 1121 | 27 | inline |  |
| 12x4 | anonymous hidden | full+reply | yes | 3448 | 26 | 2 | - |  | 2394 | 2487 | 1121 | 27 | inline |  |
| 12x4 | anonymous hidden | full+2tree | yes | 3194 | 27 | 2 | - |  | 2107 | 2200 | 1154 | 28 | inline |  |
| 12x4 | anonymous public owners | min | yes | 2657 | 20 | 1 | - |  | 1878 | 1972 | 846 | 21 | inline |  |
| 12x4 | anonymous public owners | full | yes | 3284 | 30 | 3 | 9 |  | 2037 | 2099 | 1314 | 31 | inline |  |
| 12x4 | anonymous public owners | full+spl | yes | 3652 | 37 | 3 | - |  | 2169 | 2103 | 1550 | 38 | inline |  |
| 12x4 | anonymous public owners | full+data | yes | 3682 | 30 | 3 | - |  | 2435 | 2489 | 1314 | 31 | inline |  |
| 12x4 | anonymous public owners | full+reply | yes | 3577 | 30 | 3 | - |  | 2330 | 2390 | 1314 | 31 | inline |  |
| 12x4 | anonymous public owners | full+2tree | yes | 3323 | 31 | 3 | - |  | 2043 | 2103 | 1347 | 32 | inline |  |
| 12x4 | confidential entry | min | none | 4897 | 20 | 1 | - | 801 B | 4118 | 4214 | 846 | 21 | buffered |  |
| 12x4 | confidential entry | full | none | 5452 | 30 | 3 | none | 1356 B | 4205 | 4259 | 1314 | 31 | buffered |  |
| 12x4 | confidential entry | full+spl | none | 5820 | 37 | 3 | - | 1724 B | 4337 | 4263 | 1550 | 38 | buffered |  |
| 12x4 | confidential entry | full+data | none | 5850 | 30 | 3 | - | 1754 B | 4603 | 4649 | 1314 | 31 | buffered |  |
| 12x4 | confidential entry | full+reply | none | 5452 | 30 | 3 | - | 1356 B | 4205 | 4259 | 1314 | 31 | buffered |  |
| 12x4 | confidential entry | full+2tree | none | 5491 | 31 | 3 | - | 1395 B | 4211 | 4263 | 1347 | 32 | buffered |  |
| 12x4 | anonymous entry | min | none | 5160 | 20 | 1 | - | 1064 B | 4382 | 4477 | 845 | 21 | buffered |  |
| 12x4 | anonymous entry | full | none | 5595 | 26 | 2 | none | 1499 B | 4541 | 4604 | 1121 | 27 | buffered |  |
| 12x4 | anonymous entry | full+spl | none | 5963 | 33 | 2 | - | 1867 B | 4673 | 4608 | 1357 | 34 | buffered |  |
| 12x4 | anonymous entry | full+data | none | 5993 | 26 | 2 | - | 1897 B | 4939 | 4994 | 1121 | 27 | buffered |  |
| 12x4 | anonymous entry | full+reply | none | 5888 | 26 | 2 | - | 1792 B | 4834 | 4895 | 1121 | 27 | buffered |  |
| 12x4 | anonymous entry | full+2tree | none | 5634 | 27 | 2 | - | 1538 B | 4547 | 4608 | 1154 | 28 | buffered |  |
| 12x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 12x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 12x8 | confidential signer | min | yes | 3357 | 20 | 1 | - |  | 2578 | 2818 | 846 | 21 | inline |  |
| 12x8 | confidential signer | full | yes | 3912 | 30 | 3 | 2 |  | 2665 | 2863 | 1314 | 31 | inline |  |
| 12x8 | confidential signer | full+spl | yes | 4280 | 37 | 3 | - | 184 B | 2797 | 2867 | 1550 | 38 | buffered |  |
| 12x8 | confidential signer | full+data | yes | 4706 | 30 | 3 | - | 610 B | 3459 | 3641 | 1314 | 31 | buffered |  |
| 12x8 | confidential signer | full+reply | yes | 3912 | 30 | 3 | - |  | 2665 | 2863 | 1314 | 31 | inline |  |
| 12x8 | confidential signer | full+2tree | yes | 3951 | 31 | 3 | - |  | 2671 | 2867 | 1347 | 32 | inline |  |
| 12x8 | confidential in-proof | min | yes | 3452 | 20 | 1 | - |  | 2674 | 2915 | 845 | 21 | inline |  |
| 12x8 | confidential in-proof | full | yes | 3911 | 29 | 2 | 1 |  | 2761 | 2960 | 1217 | 30 | inline |  |
| 12x8 | confidential in-proof | full+spl | yes | 4279 | 36 | 2 | - | 183 B | 2893 | 2964 | 1453 | 37 | buffered |  |
| 12x8 | confidential in-proof | full+data | yes | 4705 | 29 | 2 | - | 609 B | 3555 | 3738 | 1217 | 30 | buffered |  |
| 12x8 | confidential in-proof | full+reply | yes | 3911 | 29 | 2 | - |  | 2761 | 2960 | 1217 | 30 | inline |  |
| 12x8 | confidential in-proof | full+2tree | yes | 3950 | 30 | 2 | - |  | 2767 | 2964 | 1250 | 31 | inline |  |
| 12x8 | anonymous hidden | min | yes | 3716 | 20 | 1 | - |  | 2938 | 3209 | 845 | 21 | inline |  |
| 12x8 | anonymous hidden | full | yes | 4151 | 26 | 2 | none | 55 B | 3097 | 3336 | 1121 | 27 | buffered |  |
| 12x8 | anonymous hidden | full+spl | yes | 4519 | 33 | 2 | - | 423 B | 3229 | 3340 | 1357 | 34 | buffered |  |
| 12x8 | anonymous hidden | full+data | yes | 4945 | 26 | 2 | - | 849 B | 3891 | 4114 | 1121 | 27 | buffered |  |
| 12x8 | anonymous hidden | full+reply | yes | 4832 | 26 | 2 | - | 736 B | 3778 | 4015 | 1121 | 27 | buffered |  |
| 12x8 | anonymous hidden | full+2tree | yes | 4190 | 27 | 2 | - | 94 B | 3103 | 3340 | 1154 | 28 | buffered |  |
| 12x8 | anonymous public owners | min | yes | 3653 | 20 | 1 | - |  | 2874 | 3112 | 846 | 21 | inline |  |
| 12x8 | anonymous public owners | full | yes | 4280 | 30 | 3 | none | 184 B | 3033 | 3239 | 1314 | 31 | buffered |  |
| 12x8 | anonymous public owners | full+spl | yes | 4648 | 37 | 3 | - | 552 B | 3165 | 3243 | 1550 | 38 | buffered |  |
| 12x8 | anonymous public owners | full+data | yes | 5074 | 30 | 3 | - | 978 B | 3827 | 4017 | 1314 | 31 | buffered |  |
| 12x8 | anonymous public owners | full+reply | yes | 4961 | 30 | 3 | - | 865 B | 3714 | 3918 | 1314 | 31 | buffered |  |
| 12x8 | anonymous public owners | full+2tree | yes | 4319 | 31 | 3 | - | 223 B | 3039 | 3243 | 1347 | 32 | buffered |  |
| 12x8 | confidential entry | min | none | 5765 | 20 | 1 | - | 1669 B | 4986 | 5226 | 846 | 21 | buffered |  |
| 12x8 | confidential entry | full | none | 6320 | 30 | 3 | none | 2224 B | 5073 | 5271 | 1314 | 31 | buffered |  |
| 12x8 | confidential entry | full+spl | none | 6688 | 37 | 3 | - | 2592 B | 5205 | 5275 | 1550 | 38 | buffered |  |
| 12x8 | confidential entry | full+data | none | 7114 | 30 | 3 | - | 3018 B | 5867 | 6049 | 1314 | 31 | buffered |  |
| 12x8 | confidential entry | full+reply | none | 6320 | 30 | 3 | - | 2224 B | 5073 | 5271 | 1314 | 31 | buffered |  |
| 12x8 | confidential entry | full+2tree | none | 6359 | 31 | 3 | - | 2263 B | 5079 | 5275 | 1347 | 32 | buffered |  |
| 12x8 | anonymous entry | min | none | 6156 | 20 | 1 | - | 2060 B | 5378 | 5617 | 845 | 21 | buffered |  |
| 12x8 | anonymous entry | full | none | 6591 | 26 | 2 | none | 2495 B | 5537 | 5744 | 1121 | 27 | buffered |  |
| 12x8 | anonymous entry | full+spl | none | 6959 | 33 | 2 | - | 2863 B | 5669 | 5748 | 1357 | 34 | buffered |  |
| 12x8 | anonymous entry | full+data | none | 7385 | 26 | 2 | - | 3289 B | 6331 | 6522 | 1121 | 27 | buffered |  |
| 12x8 | anonymous entry | full+reply | none | 7272 | 26 | 2 | - | 3176 B | 6218 | 6423 | 1121 | 27 | buffered |  |
| 12x8 | anonymous entry | full+2tree | none | 6630 | 27 | 2 | - | 2534 B | 5543 | 5748 | 1154 | 28 | buffered |  |
| 12x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 12x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 16x2 | confidential signer | min | yes | 2315 | 24 | 1 | - |  | 1404 | 1432 | 978 | 25 | inline |  |
| 16x2 | confidential signer | full | yes | 2870 | 34 | 3 | 10 |  | 1491 | 1477 | 1446 | 35 | inline |  |
| 16x2 | confidential signer | full+spl | yes | 3238 | 41 | 3 | - |  | 1623 | 1481 | 1682 | 42 | inline |  |
| 16x2 | confidential signer | full+data | yes | 3070 | 34 | 3 | - |  | 1691 | 1673 | 1446 | 35 | inline |  |
| 16x2 | confidential signer | full+reply | yes | 2870 | 34 | 3 | - |  | 1491 | 1477 | 1446 | 35 | inline |  |
| 16x2 | confidential signer | full+2tree | yes | 2909 | 35 | 3 | - |  | 1497 | 1481 | 1479 | 36 | inline |  |
| 16x2 | confidential in-proof | min | yes | 2410 | 24 | 1 | - |  | 1500 | 1529 | 977 | 25 | inline |  |
| 16x2 | confidential in-proof | full | yes | 2869 | 33 | 2 | 10 |  | 1587 | 1574 | 1349 | 34 | inline |  |
| 16x2 | confidential in-proof | full+spl | yes | 3237 | 40 | 2 | - |  | 1719 | 1578 | 1585 | 41 | inline |  |
| 16x2 | confidential in-proof | full+data | yes | 3069 | 33 | 2 | - |  | 1787 | 1770 | 1349 | 34 | inline |  |
| 16x2 | confidential in-proof | full+reply | yes | 2869 | 33 | 2 | - |  | 1587 | 1574 | 1349 | 34 | inline |  |
| 16x2 | confidential in-proof | full+2tree | yes | 2908 | 34 | 2 | - |  | 1593 | 1578 | 1382 | 35 | inline |  |
| 16x2 | anonymous hidden | min | yes | 2482 | 24 | 1 | - |  | 1572 | 1631 | 977 | 25 | inline |  |
| 16x2 | anonymous hidden | full | yes | 2917 | 30 | 2 | 10 |  | 1731 | 1758 | 1253 | 31 | inline |  |
| 16x2 | anonymous hidden | full+spl | yes | 3285 | 37 | 2 | - |  | 1863 | 1762 | 1489 | 38 | inline |  |
| 16x2 | anonymous hidden | full+data | yes | 3117 | 30 | 2 | - |  | 1931 | 1954 | 1253 | 31 | inline |  |
| 16x2 | anonymous hidden | full+reply | yes | 3016 | 30 | 2 | - |  | 1830 | 1855 | 1253 | 31 | inline |  |
| 16x2 | anonymous hidden | full+2tree | yes | 2956 | 31 | 2 | - |  | 1737 | 1762 | 1286 | 32 | inline |  |
| 16x2 | anonymous public owners | min | yes | 2419 | 24 | 1 | - |  | 1508 | 1534 | 978 | 25 | inline |  |
| 16x2 | anonymous public owners | full | yes | 3046 | 34 | 3 | 10 |  | 1667 | 1661 | 1446 | 35 | inline |  |
| 16x2 | anonymous public owners | full+spl | yes | 3414 | 41 | 3 | - |  | 1799 | 1665 | 1682 | 42 | inline |  |
| 16x2 | anonymous public owners | full+data | yes | 3246 | 34 | 3 | - |  | 1867 | 1857 | 1446 | 35 | inline |  |
| 16x2 | anonymous public owners | full+reply | yes | 3145 | 34 | 3 | - |  | 1766 | 1758 | 1446 | 35 | inline |  |
| 16x2 | anonymous public owners | full+2tree | yes | 3085 | 35 | 3 | - |  | 1673 | 1665 | 1479 | 36 | inline |  |
| 16x2 | confidential entry | min | none | 5523 | 24 | 1 | - | 1427 B | 4612 | 4640 | 978 | 25 | buffered |  |
| 16x2 | confidential entry | full | none | 6078 | 34 | 3 | none | 1982 B | 4699 | 4685 | 1446 | 35 | buffered |  |
| 16x2 | confidential entry | full+spl | none | 6446 | 41 | 3 | - | 2350 B | 4831 | 4689 | 1682 | 42 | buffered |  |
| 16x2 | confidential entry | full+data | none | 6278 | 34 | 3 | - | 2182 B | 4899 | 4881 | 1446 | 35 | buffered |  |
| 16x2 | confidential entry | full+reply | none | 6078 | 34 | 3 | - | 1982 B | 4699 | 4685 | 1446 | 35 | buffered |  |
| 16x2 | confidential entry | full+2tree | none | 6117 | 35 | 3 | - | 2021 B | 4705 | 4689 | 1479 | 36 | buffered |  |
| 16x2 | anonymous entry | min | none | 5722 | 24 | 1 | - | 1626 B | 4812 | 4839 | 977 | 25 | buffered |  |
| 16x2 | anonymous entry | full | none | 6157 | 30 | 2 | none | 2061 B | 4971 | 4966 | 1253 | 31 | buffered |  |
| 16x2 | anonymous entry | full+spl | none | 6525 | 37 | 2 | - | 2429 B | 5103 | 4970 | 1489 | 38 | buffered |  |
| 16x2 | anonymous entry | full+data | none | 6357 | 30 | 2 | - | 2261 B | 5171 | 5162 | 1253 | 31 | buffered |  |
| 16x2 | anonymous entry | full+reply | none | 6256 | 30 | 2 | - | 2160 B | 5070 | 5063 | 1253 | 31 | buffered |  |
| 16x2 | anonymous entry | full+2tree | none | 6196 | 31 | 2 | - | 2100 B | 4977 | 4970 | 1286 | 32 | buffered |  |
| 16x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 16x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 16x4 | confidential signer | min | yes | 2749 | 24 | 1 | - |  | 1838 | 1938 | 978 | 25 | inline |  |
| 16x4 | confidential signer | full | yes | 3304 | 34 | 3 | 9 |  | 1925 | 1983 | 1446 | 35 | inline |  |
| 16x4 | confidential signer | full+spl | yes | 3672 | 41 | 3 | - |  | 2057 | 1987 | 1682 | 42 | inline |  |
| 16x4 | confidential signer | full+data | yes | 3702 | 34 | 3 | - |  | 2323 | 2373 | 1446 | 35 | inline |  |
| 16x4 | confidential signer | full+reply | yes | 3304 | 34 | 3 | - |  | 1925 | 1983 | 1446 | 35 | inline |  |
| 16x4 | confidential signer | full+2tree | yes | 3343 | 35 | 3 | - |  | 1931 | 1987 | 1479 | 36 | inline |  |
| 16x4 | confidential in-proof | min | yes | 2844 | 24 | 1 | - |  | 1934 | 2035 | 977 | 25 | inline |  |
| 16x4 | confidential in-proof | full | yes | 3303 | 33 | 2 | 8 |  | 2021 | 2080 | 1349 | 34 | inline |  |
| 16x4 | confidential in-proof | full+spl | yes | 3671 | 40 | 2 | - |  | 2153 | 2084 | 1585 | 41 | inline |  |
| 16x4 | confidential in-proof | full+data | yes | 3701 | 33 | 2 | - |  | 2419 | 2470 | 1349 | 34 | inline |  |
| 16x4 | confidential in-proof | full+reply | yes | 3303 | 33 | 2 | - |  | 2021 | 2080 | 1349 | 34 | inline |  |
| 16x4 | confidential in-proof | full+2tree | yes | 3342 | 34 | 2 | - |  | 2027 | 2084 | 1382 | 35 | inline |  |
| 16x4 | anonymous hidden | min | yes | 2980 | 24 | 1 | - |  | 2070 | 2201 | 977 | 25 | inline |  |
| 16x4 | anonymous hidden | full | yes | 3415 | 30 | 2 | 7 |  | 2229 | 2328 | 1253 | 31 | inline |  |
| 16x4 | anonymous hidden | full+spl | yes | 3783 | 37 | 2 | - |  | 2361 | 2332 | 1489 | 38 | inline |  |
| 16x4 | anonymous hidden | full+data | yes | 3813 | 30 | 2 | - |  | 2627 | 2718 | 1253 | 31 | inline |  |
| 16x4 | anonymous hidden | full+reply | yes | 3708 | 30 | 2 | - |  | 2522 | 2619 | 1253 | 31 | inline |  |
| 16x4 | anonymous hidden | full+2tree | yes | 3454 | 31 | 2 | - |  | 2235 | 2332 | 1286 | 32 | inline |  |
| 16x4 | anonymous public owners | min | yes | 2917 | 24 | 1 | - |  | 2006 | 2104 | 978 | 25 | inline |  |
| 16x4 | anonymous public owners | full | yes | 3544 | 34 | 3 | 6 |  | 2165 | 2231 | 1446 | 35 | inline |  |
| 16x4 | anonymous public owners | full+spl | yes | 3912 | 41 | 3 | - |  | 2297 | 2235 | 1682 | 42 | inline |  |
| 16x4 | anonymous public owners | full+data | yes | 3942 | 34 | 3 | - |  | 2563 | 2621 | 1446 | 35 | inline |  |
| 16x4 | anonymous public owners | full+reply | yes | 3837 | 34 | 3 | - |  | 2458 | 2522 | 1446 | 35 | inline |  |
| 16x4 | anonymous public owners | full+2tree | yes | 3583 | 35 | 3 | - |  | 2171 | 2235 | 1479 | 36 | inline |  |
| 16x4 | confidential entry | min | none | 5957 | 24 | 1 | - | 1861 B | 5046 | 5146 | 978 | 25 | buffered |  |
| 16x4 | confidential entry | full | none | 6512 | 34 | 3 | none | 2416 B | 5133 | 5191 | 1446 | 35 | buffered |  |
| 16x4 | confidential entry | full+spl | none | 6880 | 41 | 3 | - | 2784 B | 5265 | 5195 | 1682 | 42 | buffered |  |
| 16x4 | confidential entry | full+data | none | 6910 | 34 | 3 | - | 2814 B | 5531 | 5581 | 1446 | 35 | buffered |  |
| 16x4 | confidential entry | full+reply | none | 6512 | 34 | 3 | - | 2416 B | 5133 | 5191 | 1446 | 35 | buffered |  |
| 16x4 | confidential entry | full+2tree | none | 6551 | 35 | 3 | - | 2455 B | 5139 | 5195 | 1479 | 36 | buffered |  |
| 16x4 | anonymous entry | min | none | 6220 | 24 | 1 | - | 2124 B | 5310 | 5409 | 977 | 25 | buffered |  |
| 16x4 | anonymous entry | full | none | 6655 | 30 | 2 | none | 2559 B | 5469 | 5536 | 1253 | 31 | buffered |  |
| 16x4 | anonymous entry | full+spl | none | 7023 | 37 | 2 | - | 2927 B | 5601 | 5540 | 1489 | 38 | buffered |  |
| 16x4 | anonymous entry | full+data | none | 7053 | 30 | 2 | - | 2957 B | 5867 | 5926 | 1253 | 31 | buffered |  |
| 16x4 | anonymous entry | full+reply | none | 6948 | 30 | 2 | - | 2852 B | 5762 | 5827 | 1253 | 31 | buffered |  |
| 16x4 | anonymous entry | full+2tree | none | 6694 | 31 | 2 | - | 2598 B | 5475 | 5540 | 1286 | 32 | buffered |  |
| 16x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 16x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 16x8 | confidential signer | min | yes | 3617 | 24 | 1 | - |  | 2706 | 2950 | 978 | 25 | inline |  |
| 16x8 | confidential signer | full | yes | 4172 | 34 | 3 | none | 76 B | 2793 | 2995 | 1446 | 35 | buffered |  |
| 16x8 | confidential signer | full+spl | yes | 4540 | 41 | 3 | - | 444 B | 2925 | 2999 | 1682 | 42 | buffered |  |
| 16x8 | confidential signer | full+data | yes | 4966 | 34 | 3 | - | 870 B | 3587 | 3773 | 1446 | 35 | buffered |  |
| 16x8 | confidential signer | full+reply | yes | 4172 | 34 | 3 | - | 76 B | 2793 | 2995 | 1446 | 35 | buffered |  |
| 16x8 | confidential signer | full+2tree | yes | 4211 | 35 | 3 | - | 115 B | 2799 | 2999 | 1479 | 36 | buffered |  |
| 16x8 | confidential in-proof | min | yes | 3712 | 24 | 1 | - |  | 2802 | 3047 | 977 | 25 | inline |  |
| 16x8 | confidential in-proof | full | yes | 4171 | 33 | 2 | none | 75 B | 2889 | 3092 | 1349 | 34 | buffered |  |
| 16x8 | confidential in-proof | full+spl | yes | 4539 | 40 | 2 | - | 443 B | 3021 | 3096 | 1585 | 41 | buffered |  |
| 16x8 | confidential in-proof | full+data | yes | 4965 | 33 | 2 | - | 869 B | 3683 | 3870 | 1349 | 34 | buffered |  |
| 16x8 | confidential in-proof | full+reply | yes | 4171 | 33 | 2 | - | 75 B | 2889 | 3092 | 1349 | 34 | buffered |  |
| 16x8 | confidential in-proof | full+2tree | yes | 4210 | 34 | 2 | - | 114 B | 2895 | 3096 | 1382 | 35 | buffered |  |
| 16x8 | anonymous hidden | min | yes | 3976 | 24 | 1 | - |  | 3066 | 3341 | 977 | 25 | inline |  |
| 16x8 | anonymous hidden | full | yes | 4411 | 30 | 2 | none | 315 B | 3225 | 3468 | 1253 | 31 | buffered |  |
| 16x8 | anonymous hidden | full+spl | yes | 4779 | 37 | 2 | - | 683 B | 3357 | 3472 | 1489 | 38 | buffered |  |
| 16x8 | anonymous hidden | full+data | yes | 5205 | 30 | 2 | - | 1109 B | 4019 | 4246 | 1253 | 31 | buffered |  |
| 16x8 | anonymous hidden | full+reply | yes | 5092 | 30 | 2 | - | 996 B | 3906 | 4147 | 1253 | 31 | buffered |  |
| 16x8 | anonymous hidden | full+2tree | yes | 4450 | 31 | 2 | - | 354 B | 3231 | 3472 | 1286 | 32 | buffered |  |
| 16x8 | anonymous public owners | min | yes | 3913 | 24 | 1 | - |  | 3002 | 3244 | 978 | 25 | inline |  |
| 16x8 | anonymous public owners | full | yes | 4540 | 34 | 3 | none | 444 B | 3161 | 3371 | 1446 | 35 | buffered |  |
| 16x8 | anonymous public owners | full+spl | yes | 4908 | 41 | 3 | - | 812 B | 3293 | 3375 | 1682 | 42 | buffered |  |
| 16x8 | anonymous public owners | full+data | yes | 5334 | 34 | 3 | - | 1238 B | 3955 | 4149 | 1446 | 35 | buffered |  |
| 16x8 | anonymous public owners | full+reply | yes | 5221 | 34 | 3 | - | 1125 B | 3842 | 4050 | 1446 | 35 | buffered |  |
| 16x8 | anonymous public owners | full+2tree | yes | 4579 | 35 | 3 | - | 483 B | 3167 | 3375 | 1479 | 36 | buffered |  |
| 16x8 | confidential entry | min | none | 6825 | 24 | 1 | - | 2729 B | 5914 | 6158 | 978 | 25 | buffered |  |
| 16x8 | confidential entry | full | none | 7380 | 34 | 3 | none | 3284 B | 6001 | 6203 | 1446 | 35 | buffered |  |
| 16x8 | confidential entry | full+spl | none | 7748 | 41 | 3 | - | 3652 B | 6133 | 6207 | 1682 | 42 | buffered |  |
| 16x8 | confidential entry | full+data | none | 8174 | 34 | 3 | - | 4078 B | 6795 | 6981 | 1446 | 35 | buffered |  |
| 16x8 | confidential entry | full+reply | none | 7380 | 34 | 3 | - | 3284 B | 6001 | 6203 | 1446 | 35 | buffered |  |
| 16x8 | confidential entry | full+2tree | none | 7419 | 35 | 3 | - | 3323 B | 6007 | 6207 | 1479 | 36 | buffered |  |
| 16x8 | anonymous entry | min | none | 7216 | 24 | 1 | - | 3120 B | 6306 | 6549 | 977 | 25 | buffered |  |
| 16x8 | anonymous entry | full | none | 7651 | 30 | 2 | none | 3555 B | 6465 | 6676 | 1253 | 31 | buffered |  |
| 16x8 | anonymous entry | full+spl | none | 8019 | 37 | 2 | - | 3923 B | 6597 | 6680 | 1489 | 38 | buffered |  |
| 16x8 | anonymous entry | full+data | none | 8445 | 30 | 2 | - | 4349 B | 7259 | 7454 | 1253 | 31 | buffered |  |
| 16x8 | anonymous entry | full+reply | none | 8332 | 30 | 2 | - | 4236 B | 7146 | 7355 | 1253 | 31 | buffered |  |
| 16x8 | anonymous entry | full+2tree | none | 7690 | 31 | 2 | - | 3594 B | 6471 | 6680 | 1286 | 32 | buffered |  |
| 16x8 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 16x8 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 24x2 | confidential signer | min | yes | 2835 | 32 | 1 | - |  | 1660 | 1696 | 1242 | 33 | inline |  |
| 24x2 | confidential signer | full | yes | 3390 | 42 | 3 | 8 |  | 1747 | 1741 | 1710 | 43 | inline |  |
| 24x2 | confidential signer | full+spl | yes | 3758 | 49 | 3 | - |  | 1879 | 1745 | 1946 | 50 | inline |  |
| 24x2 | confidential signer | full+data | yes | 3590 | 42 | 3 | - |  | 1947 | 1937 | 1710 | 43 | inline |  |
| 24x2 | confidential signer | full+reply | yes | 3390 | 42 | 3 | - |  | 1747 | 1741 | 1710 | 43 | inline |  |
| 24x2 | confidential signer | full+2tree | yes | 3430 | 43 | 3 | - |  | 1754 | 1745 | 1743 | 44 | inline |  |
| 24x2 | confidential in-proof | min | yes | 2930 | 32 | 1 | - |  | 1756 | 1793 | 1241 | 33 | inline |  |
| 24x2 | confidential in-proof | full | yes | 3389 | 41 | 2 | 7 |  | 1843 | 1838 | 1613 | 42 | inline |  |
| 24x2 | confidential in-proof | full+spl | yes | 3757 | 48 | 2 | - |  | 1975 | 1842 | 1849 | 49 | inline |  |
| 24x2 | confidential in-proof | full+data | yes | 3589 | 41 | 2 | - |  | 2043 | 2034 | 1613 | 42 | inline |  |
| 24x2 | confidential in-proof | full+reply | yes | 3389 | 41 | 2 | - |  | 1843 | 1838 | 1613 | 42 | inline |  |
| 24x2 | confidential in-proof | full+2tree | yes | 3429 | 42 | 2 | - |  | 1850 | 1842 | 1646 | 43 | inline |  |
| 24x2 | anonymous hidden | min | yes | 3002 | 32 | 1 | - |  | 1828 | 1895 | 1241 | 33 | inline |  |
| 24x2 | anonymous hidden | full | yes | 3437 | 38 | 2 | 6 |  | 1987 | 2022 | 1517 | 39 | inline |  |
| 24x2 | anonymous hidden | full+spl | yes | 3805 | 45 | 2 | - |  | 2119 | 2026 | 1753 | 46 | inline |  |
| 24x2 | anonymous hidden | full+data | yes | 3637 | 38 | 2 | - |  | 2187 | 2218 | 1517 | 39 | inline |  |
| 24x2 | anonymous hidden | full+reply | yes | 3536 | 38 | 2 | - |  | 2086 | 2119 | 1517 | 39 | inline |  |
| 24x2 | anonymous hidden | full+2tree | yes | 3477 | 39 | 2 | - |  | 1994 | 2026 | 1550 | 40 | inline |  |
| 24x2 | anonymous public owners | min | yes | 2939 | 32 | 1 | - |  | 1764 | 1798 | 1242 | 33 | inline |  |
| 24x2 | anonymous public owners | full | yes | 3566 | 42 | 3 | 6 |  | 1923 | 1925 | 1710 | 43 | inline |  |
| 24x2 | anonymous public owners | full+spl | yes | 3934 | 49 | 3 | - |  | 2055 | 1929 | 1946 | 50 | inline |  |
| 24x2 | anonymous public owners | full+data | yes | 3766 | 42 | 3 | - |  | 2123 | 2121 | 1710 | 43 | inline |  |
| 24x2 | anonymous public owners | full+reply | yes | 3665 | 42 | 3 | - |  | 2022 | 2022 | 1710 | 43 | inline |  |
| 24x2 | anonymous public owners | full+2tree | yes | 3606 | 43 | 3 | - |  | 1930 | 1929 | 1743 | 44 | inline |  |
| 24x2 | confidential entry | min | none | 7643 | 32 | 1 | - | 3547 B | 6468 | 6504 | 1242 | 33 | buffered |  |
| 24x2 | confidential entry | full | none | 8198 | 42 | 3 | none | 4102 B | 6555 | 6549 | 1710 | 43 | buffered |  |
| 24x2 | confidential entry | full+spl | none | 8566 | 49 | 3 | - | 4470 B | 6687 | 6553 | 1946 | 50 | buffered |  |
| 24x2 | confidential entry | full+data | none | 8398 | 42 | 3 | - | 4302 B | 6755 | 6745 | 1710 | 43 | buffered |  |
| 24x2 | confidential entry | full+reply | none | 8198 | 42 | 3 | - | 4102 B | 6555 | 6549 | 1710 | 43 | buffered |  |
| 24x2 | confidential entry | full+2tree | none | 8238 | 43 | 3 | - | 4142 B | 6562 | 6553 | 1743 | 44 | buffered |  |
| 24x2 | anonymous entry | min | none | 7842 | 32 | 1 | - | 3746 B | 6668 | 6703 | 1241 | 33 | buffered |  |
| 24x2 | anonymous entry | full | none | 8277 | 38 | 2 | none | 4181 B | 6827 | 6830 | 1517 | 39 | buffered |  |
| 24x2 | anonymous entry | full+spl | none | 8645 | 45 | 2 | - | 4549 B | 6959 | 6834 | 1753 | 46 | buffered |  |
| 24x2 | anonymous entry | full+data | none | 8477 | 38 | 2 | - | 4381 B | 7027 | 7026 | 1517 | 39 | buffered |  |
| 24x2 | anonymous entry | full+reply | none | 8376 | 38 | 2 | - | 4280 B | 6926 | 6927 | 1517 | 39 | buffered |  |
| 24x2 | anonymous entry | full+2tree | none | 8317 | 39 | 2 | - | 4221 B | 6834 | 6834 | 1550 | 40 | buffered |  |
| 24x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 24x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 24x4 | confidential signer | min | yes | 3269 | 32 | 1 | - |  | 2094 | 2202 | 1242 | 33 | inline |  |
| 24x4 | confidential signer | full | yes | 3824 | 42 | 3 | 3 |  | 2181 | 2247 | 1710 | 43 | inline |  |
| 24x4 | confidential signer | full+spl | yes | 4192 | 49 | 3 | - | 96 B | 2313 | 2251 | 1946 | 50 | buffered |  |
| 24x4 | confidential signer | full+data | yes | 4222 | 42 | 3 | - | 126 B | 2579 | 2637 | 1710 | 43 | buffered |  |
| 24x4 | confidential signer | full+reply | yes | 3824 | 42 | 3 | - |  | 2181 | 2247 | 1710 | 43 | inline |  |
| 24x4 | confidential signer | full+2tree | yes | 3864 | 43 | 3 | - |  | 2188 | 2251 | 1743 | 44 | inline |  |
| 24x4 | confidential in-proof | min | yes | 3364 | 32 | 1 | - |  | 2190 | 2299 | 1241 | 33 | inline |  |
| 24x4 | confidential in-proof | full | yes | 3823 | 41 | 2 | 2 |  | 2277 | 2344 | 1613 | 42 | inline |  |
| 24x4 | confidential in-proof | full+spl | yes | 4191 | 48 | 2 | - | 95 B | 2409 | 2348 | 1849 | 49 | buffered |  |
| 24x4 | confidential in-proof | full+data | yes | 4221 | 41 | 2 | - | 125 B | 2675 | 2734 | 1613 | 42 | buffered |  |
| 24x4 | confidential in-proof | full+reply | yes | 3823 | 41 | 2 | - |  | 2277 | 2344 | 1613 | 42 | inline |  |
| 24x4 | confidential in-proof | full+2tree | yes | 3863 | 42 | 2 | - |  | 2284 | 2348 | 1646 | 43 | inline |  |
| 24x4 | anonymous hidden | min | yes | 3500 | 32 | 1 | - |  | 2326 | 2465 | 1241 | 33 | inline |  |
| 24x4 | anonymous hidden | full | yes | 3935 | 38 | 2 | 1 |  | 2485 | 2592 | 1517 | 39 | inline |  |
| 24x4 | anonymous hidden | full+spl | yes | 4303 | 45 | 2 | - | 207 B | 2617 | 2596 | 1753 | 46 | buffered |  |
| 24x4 | anonymous hidden | full+data | yes | 4333 | 38 | 2 | - | 237 B | 2883 | 2982 | 1517 | 39 | buffered |  |
| 24x4 | anonymous hidden | full+reply | yes | 4228 | 38 | 2 | - | 132 B | 2778 | 2883 | 1517 | 39 | buffered |  |
| 24x4 | anonymous hidden | full+2tree | yes | 3975 | 39 | 2 | - |  | 2492 | 2596 | 1550 | 40 | inline |  |
| 24x4 | anonymous public owners | min | yes | 3437 | 32 | 1 | - |  | 2262 | 2368 | 1242 | 33 | inline |  |
| 24x4 | anonymous public owners | full | yes | 4064 | 42 | 3 | 1 |  | 2421 | 2495 | 1710 | 43 | inline |  |
| 24x4 | anonymous public owners | full+spl | yes | 4432 | 49 | 3 | - | 336 B | 2553 | 2499 | 1946 | 50 | buffered |  |
| 24x4 | anonymous public owners | full+data | yes | 4462 | 42 | 3 | - | 366 B | 2819 | 2885 | 1710 | 43 | buffered |  |
| 24x4 | anonymous public owners | full+reply | yes | 4357 | 42 | 3 | - | 261 B | 2714 | 2786 | 1710 | 43 | buffered |  |
| 24x4 | anonymous public owners | full+2tree | yes | 4104 | 43 | 3 | - | 8 B | 2428 | 2499 | 1743 | 44 | buffered |  |
| 24x4 | confidential entry | min | none | 8077 | 32 | 1 | - | 3981 B | 6902 | 7010 | 1242 | 33 | buffered |  |
| 24x4 | confidential entry | full | none | 8632 | 42 | 3 | none | 4536 B | 6989 | 7055 | 1710 | 43 | buffered |  |
| 24x4 | confidential entry | full+spl | none | 9000 | 49 | 3 | - | 4904 B | 7121 | 7059 | 1946 | 50 | buffered |  |
| 24x4 | confidential entry | full+data | none | 9030 | 42 | 3 | - | 4934 B | 7387 | 7445 | 1710 | 43 | buffered |  |
| 24x4 | confidential entry | full+reply | none | 8632 | 42 | 3 | - | 4536 B | 6989 | 7055 | 1710 | 43 | buffered |  |
| 24x4 | confidential entry | full+2tree | none | 8672 | 43 | 3 | - | 4576 B | 6996 | 7059 | 1743 | 44 | buffered |  |
| 24x4 | anonymous entry | min | none | 8340 | 32 | 1 | - | 4244 B | 7166 | 7273 | 1241 | 33 | buffered |  |
| 24x4 | anonymous entry | full | none | 8775 | 38 | 2 | none | 4679 B | 7325 | 7400 | 1517 | 39 | buffered |  |
| 24x4 | anonymous entry | full+spl | none | 9143 | 45 | 2 | - | 5047 B | 7457 | 7404 | 1753 | 46 | buffered |  |
| 24x4 | anonymous entry | full+data | none | 9173 | 38 | 2 | - | 5077 B | 7723 | 7790 | 1517 | 39 | buffered |  |
| 24x4 | anonymous entry | full+reply | none | 9068 | 38 | 2 | - | 4972 B | 7618 | 7691 | 1517 | 39 | buffered |  |
| 24x4 | anonymous entry | full+2tree | none | 8815 | 39 | 2 | - | 4719 B | 7332 | 7404 | 1550 | 40 | buffered |  |
| 24x4 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 24x4 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 32x2 | confidential signer | min | none | 3355 | 40 | 1 | - |  | 1916 | 1960 | 1506 | 41 | inline |  |
| 32x2 | confidential signer | full | none | 3910 | 50 | 3 | 2 |  | 2003 | 2005 | 1974 | 51 | inline |  |
| 32x2 | confidential signer | full+spl | none | 4278 | 57 | 3 | - | 182 B | 2135 | 2009 | 2210 | 58 | buffered |  |
| 32x2 | confidential signer | full+data | none | 4110 | 50 | 3 | - | 14 B | 2203 | 2201 | 1974 | 51 | buffered |  |
| 32x2 | confidential signer | full+reply | none | 3910 | 50 | 3 | - |  | 2003 | 2005 | 1974 | 51 | inline |  |
| 32x2 | confidential signer | full+2tree | none | 3951 | 51 | 3 | - |  | 2011 | 2009 | 2007 | 52 | inline |  |
| 32x2 | confidential in-proof | min | none | 3450 | 40 | 1 | - |  | 2012 | 2057 | 1505 | 41 | inline |  |
| 32x2 | confidential in-proof | full | none | 3909 | 49 | 2 | 1 |  | 2099 | 2102 | 1877 | 50 | inline |  |
| 32x2 | confidential in-proof | full+spl | none | 4277 | 56 | 2 | - | 181 B | 2231 | 2106 | 2113 | 57 | buffered |  |
| 32x2 | confidential in-proof | full+data | none | 4109 | 49 | 2 | - | 13 B | 2299 | 2298 | 1877 | 50 | buffered |  |
| 32x2 | confidential in-proof | full+reply | none | 3909 | 49 | 2 | - |  | 2099 | 2102 | 1877 | 50 | inline |  |
| 32x2 | confidential in-proof | full+2tree | none | 3950 | 50 | 2 | - |  | 2107 | 2106 | 1910 | 51 | inline |  |
| 32x2 | anonymous hidden | min | none | 3522 | 40 | 1 | - |  | 2084 | 2159 | 1505 | 41 | inline |  |
| 32x2 | anonymous hidden | full | none | 3957 | 46 | 2 | 1 |  | 2243 | 2286 | 1781 | 47 | inline |  |
| 32x2 | anonymous hidden | full+spl | none | 4325 | 53 | 2 | - | 229 B | 2375 | 2290 | 2017 | 54 | buffered |  |
| 32x2 | anonymous hidden | full+data | none | 4157 | 46 | 2 | - | 61 B | 2443 | 2482 | 1781 | 47 | buffered |  |
| 32x2 | anonymous hidden | full+reply | none | 4056 | 46 | 2 | - |  | 2342 | 2383 | 1781 | 47 | inline |  |
| 32x2 | anonymous hidden | full+2tree | none | 3998 | 47 | 2 | - |  | 2251 | 2290 | 1814 | 48 | inline |  |
| 32x2 | anonymous public owners | min | none | 3459 | 40 | 1 | - |  | 2020 | 2062 | 1506 | 41 | inline |  |
| 32x2 | anonymous public owners | full | none | 4086 | 50 | 3 | 1 |  | 2179 | 2189 | 1974 | 51 | inline |  |
| 32x2 | anonymous public owners | full+spl | none | 4454 | 57 | 3 | - | 358 B | 2311 | 2193 | 2210 | 58 | buffered |  |
| 32x2 | anonymous public owners | full+data | none | 4286 | 50 | 3 | - | 190 B | 2379 | 2385 | 1974 | 51 | buffered |  |
| 32x2 | anonymous public owners | full+reply | none | 4185 | 50 | 3 | - | 89 B | 2278 | 2286 | 1974 | 51 | buffered |  |
| 32x2 | anonymous public owners | full+2tree | none | 4127 | 51 | 3 | - | 31 B | 2187 | 2193 | 2007 | 52 | buffered |  |
| 32x2 | confidential entry | min | none | 9763 | 40 | 1 | - | 5667 B | 8324 | 8368 | 1506 | 41 | buffered |  |
| 32x2 | confidential entry | full | none | 10318 | 50 | 3 | none | 6222 B | 8411 | 8413 | 1974 | 51 | buffered |  |
| 32x2 | confidential entry | full+spl | none | 10686 | 57 | 3 | - | 6590 B | 8543 | 8417 | 2210 | 58 | buffered |  |
| 32x2 | confidential entry | full+data | none | 10518 | 50 | 3 | - | 6422 B | 8611 | 8609 | 1974 | 51 | buffered |  |
| 32x2 | confidential entry | full+reply | none | 10318 | 50 | 3 | - | 6222 B | 8411 | 8413 | 1974 | 51 | buffered |  |
| 32x2 | confidential entry | full+2tree | none | 10359 | 51 | 3 | - | 6263 B | 8419 | 8417 | 2007 | 52 | buffered |  |
| 32x2 | anonymous entry | min | none | 9962 | 40 | 1 | - | 5866 B | 8524 | 8567 | 1505 | 41 | buffered |  |
| 32x2 | anonymous entry | full | none | 10397 | 46 | 2 | none | 6301 B | 8683 | 8694 | 1781 | 47 | buffered |  |
| 32x2 | anonymous entry | full+spl | none | 10765 | 53 | 2 | - | 6669 B | 8815 | 8698 | 2017 | 54 | buffered |  |
| 32x2 | anonymous entry | full+data | none | 10597 | 46 | 2 | - | 6501 B | 8883 | 8890 | 1781 | 47 | buffered |  |
| 32x2 | anonymous entry | full+reply | none | 10496 | 46 | 2 | - | 6400 B | 8782 | 8791 | 1781 | 47 | buffered |  |
| 32x2 | anonymous entry | full+2tree | none | 10438 | 47 | 2 | - | 6342 B | 8691 | 8698 | 1814 | 48 | buffered |  |
| 32x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 32x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 40x2 | confidential signer | min | none | 3875 | 48 | 1 | - |  | 2172 | 2224 | 1770 | 49 | inline |  |
| 40x2 | confidential signer | full | none | 4430 | 58 | 3 | none | 334 B | 2259 | 2269 | 2238 | 59 | buffered |  |
| 40x2 | confidential signer | full+spl | none | 4798 | 65 | 3 | - | 702 B, 1 accounts | 2391 | 2273 | 2474 | 66 | no | 2 accounts |
| 40x2 | confidential signer | full+data | none | 4630 | 58 | 3 | - | 534 B | 2459 | 2465 | 2238 | 59 | buffered |  |
| 40x2 | confidential signer | full+reply | none | 4430 | 58 | 3 | - | 334 B | 2259 | 2269 | 2238 | 59 | buffered |  |
| 40x2 | confidential signer | full+2tree | none | 4472 | 59 | 3 | - | 376 B | 2268 | 2273 | 2271 | 60 | buffered |  |
| 40x2 | confidential in-proof | min | none | 3970 | 48 | 1 | - |  | 2268 | 2321 | 1769 | 49 | inline |  |
| 40x2 | confidential in-proof | full | none | 4429 | 57 | 2 | none | 333 B | 2355 | 2366 | 2141 | 58 | buffered |  |
| 40x2 | confidential in-proof | full+spl | none | 4797 | 64 | 2 | - | 701 B | 2487 | 2370 | 2377 | 65 | no | 1 accounts |
| 40x2 | confidential in-proof | full+data | none | 4629 | 57 | 2 | - | 533 B | 2555 | 2562 | 2141 | 58 | buffered |  |
| 40x2 | confidential in-proof | full+reply | none | 4429 | 57 | 2 | - | 333 B | 2355 | 2366 | 2141 | 58 | buffered |  |
| 40x2 | confidential in-proof | full+2tree | none | 4471 | 58 | 2 | - | 375 B | 2364 | 2370 | 2174 | 59 | buffered |  |
| 40x2 | anonymous hidden | min | none | 4042 | 48 | 1 | - |  | 2340 | 2423 | 1769 | 49 | inline |  |
| 40x2 | anonymous hidden | full | none | 4477 | 54 | 2 | none | 381 B | 2499 | 2550 | 2045 | 55 | buffered |  |
| 40x2 | anonymous hidden | full+spl | none | 4845 | 61 | 2 | - | 749 B | 2631 | 2554 | 2281 | 62 | buffered |  |
| 40x2 | anonymous hidden | full+data | none | 4677 | 54 | 2 | - | 581 B | 2699 | 2746 | 2045 | 55 | buffered |  |
| 40x2 | anonymous hidden | full+reply | none | 4576 | 54 | 2 | - | 480 B | 2598 | 2647 | 2045 | 55 | buffered |  |
| 40x2 | anonymous hidden | full+2tree | none | 4519 | 55 | 2 | - | 423 B | 2508 | 2554 | 2078 | 56 | buffered |  |
| 40x2 | anonymous public owners | min | none | 3979 | 48 | 1 | - |  | 2276 | 2326 | 1770 | 49 | inline |  |
| 40x2 | anonymous public owners | full | none | 4606 | 58 | 3 | none | 510 B | 2435 | 2453 | 2238 | 59 | buffered |  |
| 40x2 | anonymous public owners | full+spl | none | 4974 | 65 | 3 | - | 878 B, 1 accounts | 2567 | 2457 | 2474 | 66 | no | 2 accounts |
| 40x2 | anonymous public owners | full+data | none | 4806 | 58 | 3 | - | 710 B | 2635 | 2649 | 2238 | 59 | buffered |  |
| 40x2 | anonymous public owners | full+reply | none | 4705 | 58 | 3 | - | 609 B | 2534 | 2550 | 2238 | 59 | buffered |  |
| 40x2 | anonymous public owners | full+2tree | none | 4648 | 59 | 3 | - | 552 B | 2444 | 2457 | 2271 | 60 | buffered |  |
| 40x2 | confidential entry | min | none | 11883 | 48 | 1 | - | 7787 B | 10180 | 10232 | 1770 | 49 | buffered |  |
| 40x2 | confidential entry | full | none | 12438 | 58 | 3 | none | 8342 B | 10267 | 10277 | 2238 | 59 | no | buffer create 61 B, SPP CPI 37 B |
| 40x2 | confidential entry | full+spl | none | 12806 | 65 | 3 | - | 8710 B, 1 accounts | 10399 | 10281 | 2474 | 66 | no | 2 accounts, buffer create 193 B, SPP CPI 41 B |
| 40x2 | confidential entry | full+data | none | 12638 | 58 | 3 | - | 8542 B | 10467 | 10473 | 2238 | 59 | no | buffer create 261 B, SPP CPI 233 B |
| 40x2 | confidential entry | full+reply | none | 12438 | 58 | 3 | - | 8342 B | 10267 | 10277 | 2238 | 59 | no | buffer create 61 B, SPP CPI 37 B |
| 40x2 | confidential entry | full+2tree | none | 12480 | 59 | 3 | - | 8384 B | 10276 | 10281 | 2271 | 60 | no | buffer create 70 B, SPP CPI 41 B |
| 40x2 | anonymous entry | min | none | 12082 | 48 | 1 | - | 7986 B | 10380 | 10431 | 1769 | 49 | no | buffer create 174 B, SPP CPI 191 B |
| 40x2 | anonymous entry | full | none | 12517 | 54 | 2 | none | 8421 B | 10539 | 10558 | 2045 | 55 | no | buffer create 333 B, SPP CPI 318 B |
| 40x2 | anonymous entry | full+spl | none | 12885 | 61 | 2 | - | 8789 B | 10671 | 10562 | 2281 | 62 | no | buffer create 465 B, SPP CPI 322 B |
| 40x2 | anonymous entry | full+data | none | 12717 | 54 | 2 | - | 8621 B | 10739 | 10754 | 2045 | 55 | no | buffer create 533 B, SPP CPI 514 B |
| 40x2 | anonymous entry | full+reply | none | 12616 | 54 | 2 | - | 8520 B | 10638 | 10655 | 2045 | 55 | no | buffer create 432 B, SPP CPI 415 B |
| 40x2 | anonymous entry | full+2tree | none | 12559 | 55 | 2 | - | 8463 B | 10548 | 10562 | 2078 | 56 | no | buffer create 342 B, SPP CPI 322 B |
| 40x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 40x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 48x2 | confidential signer | min | none | 4395 | 56 | 1 | - | 299 B | 2428 | 2488 | 2034 | 57 | buffered |  |
| 48x2 | confidential signer | full | none | 4950 | 66 | 3 | none | 854 B, 2 accounts | 2515 | 2533 | 2502 | 67 | no | 3 accounts |
| 48x2 | confidential signer | full+spl | none | 5318 | 73 | 3 | - | 1222 B, 9 accounts | 2647 | 2537 | 2738 | 74 | no | 10 accounts |
| 48x2 | confidential signer | full+data | none | 5150 | 66 | 3 | - | 1054 B, 2 accounts | 2715 | 2729 | 2502 | 67 | no | 3 accounts |
| 48x2 | confidential signer | full+reply | none | 4950 | 66 | 3 | - | 854 B, 2 accounts | 2515 | 2533 | 2502 | 67 | no | 3 accounts |
| 48x2 | confidential signer | full+2tree | none | 4993 | 67 | 3 | - | 897 B, 3 accounts | 2525 | 2537 | 2535 | 68 | no | 4 accounts |
| 48x2 | confidential in-proof | min | none | 4490 | 56 | 1 | - | 394 B | 2524 | 2585 | 2033 | 57 | buffered |  |
| 48x2 | confidential in-proof | full | none | 4949 | 65 | 2 | none | 853 B, 1 accounts | 2611 | 2630 | 2405 | 66 | no | 2 accounts |
| 48x2 | confidential in-proof | full+spl | none | 5317 | 72 | 2 | - | 1221 B, 8 accounts | 2743 | 2634 | 2641 | 73 | no | 9 accounts |
| 48x2 | confidential in-proof | full+data | none | 5149 | 65 | 2 | - | 1053 B, 1 accounts | 2811 | 2826 | 2405 | 66 | no | 2 accounts |
| 48x2 | confidential in-proof | full+reply | none | 4949 | 65 | 2 | - | 853 B, 1 accounts | 2611 | 2630 | 2405 | 66 | no | 2 accounts |
| 48x2 | confidential in-proof | full+2tree | none | 4992 | 66 | 2 | - | 896 B, 2 accounts | 2621 | 2634 | 2438 | 67 | no | 3 accounts |
| 48x2 | anonymous hidden | min | none | 4562 | 56 | 1 | - | 466 B | 2596 | 2687 | 2033 | 57 | buffered |  |
| 48x2 | anonymous hidden | full | none | 4997 | 62 | 2 | none | 901 B | 2755 | 2814 | 2309 | 63 | buffered |  |
| 48x2 | anonymous hidden | full+spl | none | 5365 | 69 | 2 | - | 1269 B, 5 accounts | 2887 | 2818 | 2545 | 70 | no | 6 accounts |
| 48x2 | anonymous hidden | full+data | none | 5197 | 62 | 2 | - | 1101 B | 2955 | 3010 | 2309 | 63 | buffered |  |
| 48x2 | anonymous hidden | full+reply | none | 5096 | 62 | 2 | - | 1000 B | 2854 | 2911 | 2309 | 63 | buffered |  |
| 48x2 | anonymous hidden | full+2tree | none | 5040 | 63 | 2 | - | 944 B | 2765 | 2818 | 2342 | 64 | buffered |  |
| 48x2 | anonymous public owners | min | none | 4499 | 56 | 1 | - | 403 B | 2532 | 2590 | 2034 | 57 | buffered |  |
| 48x2 | anonymous public owners | full | none | 5126 | 66 | 3 | none | 1030 B, 2 accounts | 2691 | 2717 | 2502 | 67 | no | 3 accounts |
| 48x2 | anonymous public owners | full+spl | none | 5494 | 73 | 3 | - | 1398 B, 9 accounts | 2823 | 2721 | 2738 | 74 | no | 10 accounts |
| 48x2 | anonymous public owners | full+data | none | 5326 | 66 | 3 | - | 1230 B, 2 accounts | 2891 | 2913 | 2502 | 67 | no | 3 accounts |
| 48x2 | anonymous public owners | full+reply | none | 5225 | 66 | 3 | - | 1129 B, 2 accounts | 2790 | 2814 | 2502 | 67 | no | 3 accounts |
| 48x2 | anonymous public owners | full+2tree | none | 5169 | 67 | 3 | - | 1073 B, 3 accounts | 2701 | 2721 | 2535 | 68 | no | 4 accounts |
| 48x2 | confidential entry | min | none | 14003 | 56 | 1 | - | 9907 B | 12036 | 12096 | 2034 | 57 | no | buffer create 1830 B, SPP CPI 1856 B |
| 48x2 | confidential entry | full | none | 14558 | 66 | 3 | none | 10462 B, 2 accounts | 12123 | 12141 | 2502 | 67 | no | 3 accounts, buffer create 1917 B, SPP CPI 1901 B |
| 48x2 | confidential entry | full+spl | none | 14926 | 73 | 3 | - | 10830 B, 9 accounts | 12255 | 12145 | 2738 | 74 | no | 10 accounts, buffer create 2049 B, SPP CPI 1905 B |
| 48x2 | confidential entry | full+data | none | 14758 | 66 | 3 | - | 10662 B, 2 accounts | 12323 | 12337 | 2502 | 67 | no | 3 accounts, buffer create 2117 B, SPP CPI 2097 B |
| 48x2 | confidential entry | full+reply | none | 14558 | 66 | 3 | - | 10462 B, 2 accounts | 12123 | 12141 | 2502 | 67 | no | 3 accounts, buffer create 1917 B, SPP CPI 1901 B |
| 48x2 | confidential entry | full+2tree | none | 14601 | 67 | 3 | - | 10505 B, 3 accounts | 12133 | 12145 | 2535 | 68 | no | 4 accounts, buffer create 1927 B, SPP CPI 1905 B |
| 48x2 | anonymous entry | min | none | 14202 | 56 | 1 | - | 10106 B | 12236 | 12295 | 2033 | 57 | no | buffer create 2030 B, SPP CPI 2055 B |
| 48x2 | anonymous entry | full | none | 14637 | 62 | 2 | none | 10541 B | 12395 | 12422 | 2309 | 63 | no | buffer create 2189 B, SPP CPI 2182 B |
| 48x2 | anonymous entry | full+spl | none | 15005 | 69 | 2 | - | 10909 B, 5 accounts | 12527 | 12426 | 2545 | 70 | no | 6 accounts, buffer create 2321 B, SPP CPI 2186 B |
| 48x2 | anonymous entry | full+data | none | 14837 | 62 | 2 | - | 10741 B | 12595 | 12618 | 2309 | 63 | no | buffer create 2389 B, SPP CPI 2378 B |
| 48x2 | anonymous entry | full+reply | none | 14736 | 62 | 2 | - | 10640 B | 12494 | 12519 | 2309 | 63 | no | buffer create 2288 B, SPP CPI 2279 B |
| 48x2 | anonymous entry | full+2tree | none | 14680 | 63 | 2 | - | 10584 B | 12405 | 12426 | 2342 | 64 | no | buffer create 2199 B, SPP CPI 2186 B |
| 48x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 48x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 49x2 | confidential signer | min | none | 4460 | 57 | 1 | - | 364 B | 2460 | 2521 | 2067 | 58 | buffered |  |
| 49x2 | confidential signer | full | none | 5015 | 67 | 3 | none | 919 B, 3 accounts | 2547 | 2566 | 2535 | 68 | no | 4 accounts |
| 49x2 | confidential signer | full+spl | none | 5383 | 74 | 3 | - | 1287 B, 10 accounts | 2679 | 2570 | 2771 | 75 | no | 11 accounts |
| 49x2 | confidential signer | full+data | none | 5215 | 67 | 3 | - | 1119 B, 3 accounts | 2747 | 2762 | 2535 | 68 | no | 4 accounts |
| 49x2 | confidential signer | full+reply | none | 5015 | 67 | 3 | - | 919 B, 3 accounts | 2547 | 2566 | 2535 | 68 | no | 4 accounts |
| 49x2 | confidential signer | full+2tree | none | 5059 | 68 | 3 | - | 963 B, 4 accounts | 2558 | 2570 | 2568 | 69 | no | 5 accounts |
| 49x2 | confidential in-proof | min | none | 4555 | 57 | 1 | - | 459 B | 2556 | 2618 | 2066 | 58 | buffered |  |
| 49x2 | confidential in-proof | full | none | 5014 | 66 | 2 | none | 918 B, 2 accounts | 2643 | 2663 | 2438 | 67 | no | 3 accounts |
| 49x2 | confidential in-proof | full+spl | none | 5382 | 73 | 2 | - | 1286 B, 9 accounts | 2775 | 2667 | 2674 | 74 | no | 10 accounts |
| 49x2 | confidential in-proof | full+data | none | 5214 | 66 | 2 | - | 1118 B, 2 accounts | 2843 | 2859 | 2438 | 67 | no | 3 accounts |
| 49x2 | confidential in-proof | full+reply | none | 5014 | 66 | 2 | - | 918 B, 2 accounts | 2643 | 2663 | 2438 | 67 | no | 3 accounts |
| 49x2 | confidential in-proof | full+2tree | none | 5058 | 67 | 2 | - | 962 B, 3 accounts | 2654 | 2667 | 2471 | 68 | no | 4 accounts |
| 49x2 | anonymous hidden | min | none | 4627 | 57 | 1 | - | 531 B | 2628 | 2720 | 2066 | 58 | buffered |  |
| 49x2 | anonymous hidden | full | none | 5062 | 63 | 2 | none | 966 B | 2787 | 2847 | 2342 | 64 | buffered |  |
| 49x2 | anonymous hidden | full+spl | none | 5430 | 70 | 2 | - | 1334 B, 6 accounts | 2919 | 2851 | 2578 | 71 | no | 7 accounts |
| 49x2 | anonymous hidden | full+data | none | 5262 | 63 | 2 | - | 1166 B | 2987 | 3043 | 2342 | 64 | buffered |  |
| 49x2 | anonymous hidden | full+reply | none | 5161 | 63 | 2 | - | 1065 B | 2886 | 2944 | 2342 | 64 | buffered |  |
| 49x2 | anonymous hidden | full+2tree | none | 5106 | 64 | 2 | - | 1010 B | 2798 | 2851 | 2375 | 65 | no | 1 accounts |
| 49x2 | anonymous public owners | min | none | 4564 | 57 | 1 | - | 468 B | 2564 | 2623 | 2067 | 58 | buffered |  |
| 49x2 | anonymous public owners | full | none | 5191 | 67 | 3 | none | 1095 B, 3 accounts | 2723 | 2750 | 2535 | 68 | no | 4 accounts |
| 49x2 | anonymous public owners | full+spl | none | 5559 | 74 | 3 | - | 1463 B, 10 accounts | 2855 | 2754 | 2771 | 75 | no | 11 accounts |
| 49x2 | anonymous public owners | full+data | none | 5391 | 67 | 3 | - | 1295 B, 3 accounts | 2923 | 2946 | 2535 | 68 | no | 4 accounts |
| 49x2 | anonymous public owners | full+reply | none | 5290 | 67 | 3 | - | 1194 B, 3 accounts | 2822 | 2847 | 2535 | 68 | no | 4 accounts |
| 49x2 | anonymous public owners | full+2tree | none | 5235 | 68 | 3 | - | 1139 B, 4 accounts | 2734 | 2754 | 2568 | 69 | no | 5 accounts |
| 49x2 | confidential entry | min | none | 14268 | 57 | 1 | - | 10172 B | 12268 | 12329 | 2067 | 58 | no | buffer create 2062 B, SPP CPI 2089 B |
| 49x2 | confidential entry | full | none | 14823 | 67 | 3 | none | 10727 B, 3 accounts | 12355 | 12374 | 2535 | 68 | no | 4 accounts, buffer create 2149 B, SPP CPI 2134 B |
| 49x2 | confidential entry | full+spl | none | 15191 | 74 | 3 | - | 11095 B, 10 accounts | 12487 | 12378 | 2771 | 75 | no | 11 accounts, buffer create 2281 B, SPP CPI 2138 B |
| 49x2 | confidential entry | full+data | none | 15023 | 67 | 3 | - | 10927 B, 3 accounts | 12555 | 12570 | 2535 | 68 | no | 4 accounts, buffer create 2349 B, SPP CPI 2330 B |
| 49x2 | confidential entry | full+reply | none | 14823 | 67 | 3 | - | 10727 B, 3 accounts | 12355 | 12374 | 2535 | 68 | no | 4 accounts, buffer create 2149 B, SPP CPI 2134 B |
| 49x2 | confidential entry | full+2tree | none | 14867 | 68 | 3 | - | 10771 B, 4 accounts | 12366 | 12378 | 2568 | 69 | no | 5 accounts, buffer create 2160 B, SPP CPI 2138 B |
| 49x2 | anonymous entry | min | none | 14467 | 57 | 1 | - | 10371 B | 12468 | 12528 | 2066 | 58 | no | buffer create 2262 B, SPP CPI 2288 B |
| 49x2 | anonymous entry | full | none | 14902 | 63 | 2 | none | 10806 B | 12627 | 12655 | 2342 | 64 | no | buffer create 2421 B, SPP CPI 2415 B |
| 49x2 | anonymous entry | full+spl | none | 15270 | 70 | 2 | - | 11174 B, 6 accounts | 12759 | 12659 | 2578 | 71 | no | 7 accounts, buffer create 2553 B, SPP CPI 2419 B |
| 49x2 | anonymous entry | full+data | none | 15102 | 63 | 2 | - | 11006 B | 12827 | 12851 | 2342 | 64 | no | buffer create 2621 B, SPP CPI 2611 B |
| 49x2 | anonymous entry | full+reply | none | 15001 | 63 | 2 | - | 10905 B | 12726 | 12752 | 2342 | 64 | no | buffer create 2520 B, SPP CPI 2512 B |
| 49x2 | anonymous entry | full+2tree | none | 14946 | 64 | 2 | - | 10850 B | 12638 | 12659 | 2375 | 65 | no | 1 accounts, buffer create 2432 B, SPP CPI 2419 B |
| 49x2 | delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 49x2 | anonymous delegate | - | - | - | - | - | - | - | - | - | - | - | no | rail |
| 8x1 | merge | ring | yes | 1640 | 16 | 1 | - |  | - | - | - | - | inline |  |
| 8x1 | merge | owner signed | yes | 1737 | 17 | 2 | - |  | - | - | - | - | inline |  |
| 24x1 | merge | ring | yes | 2680 | 32 | 1 | - |  | - | - | - | - | inline |  |
| 24x1 | merge | owner signed | yes | 2777 | 33 | 2 | - |  | - | - | - | - | inline |  |
| 52x1 | merge | ring | yes | 4500 | 60 | 1 | - | 404 B | - | - | - | - | no | 404 B |
| 52x1 | merge | owner signed | yes | 4597 | 61 | 2 | - | 501 B | - | - | - | - | no | 501 B |
| 0x1 | deposit | min | yes | 1014 | 9 | 1 | - |  | - | - | - | - | inline |  |
| 0x1 | deposit | full | yes | 1285 | 15 | 2 | - |  | - | - | - | - | inline |  |
| 0x2 | deposit | min | yes | 1392 | 9 | 1 | - |  | - | - | - | - | inline |  |
| 0x2 | deposit | full | yes | 1663 | 15 | 2 | - |  | - | - | - | - | inline |  |
| 0x4 | deposit | min | yes | 2148 | 9 | 1 | - |  | - | - | - | - | inline |  |
| 0x4 | deposit | full | yes | 2419 | 15 | 2 | - |  | - | - | - | - | inline |  |
| 0x8 | deposit | min | yes | 3660 | 9 | 1 | - |  | - | - | - | - | inline |  |
| 0x8 | deposit | full | yes | 3931 | 15 | 2 | - |  | - | - | - | - | inline |  |
