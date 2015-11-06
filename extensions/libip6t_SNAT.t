:POSTROUTING
*nat
-j SNAT --to-source dead::beef;=;OK
-j SNAT --to-source dead::beef-dead::fee7;=;OK
-p tcp -j SNAT --to-source [dead::beef]:1025-65535;=;OK
-p tcp -j SNAT --to-source [dead::beef-dead::fee7]:1025-65535;=;OK
-p tcp -j SNAT --to-source [dead::beef-dead::fee7]:1025-65536;;FAIL
-j SNAT;;FAIL
