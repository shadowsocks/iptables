:PREROUTING,INPUT
*mangle
-m socket;=;OK
-m socket --transparent --nowildcard;=;OK
