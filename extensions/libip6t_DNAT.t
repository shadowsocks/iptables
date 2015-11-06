:PREROUTING
*nat
-j DNAT --to-destination dead::beef;=;OK
-j DNAT --to-destination dead::beef-dead::fee7;=;OK
-p tcp -j DNAT --to-destination [dead::beef]:1025-65535;=;OK
-p tcp -j DNAT --to-destination [dead::beef-dead::fee7]:1025-65535;=;OK
-p tcp -j DNAT --to-destination [dead::beef-dead::fee7]:1025-65536;;FAIL
-j DNAT;;FAIL
