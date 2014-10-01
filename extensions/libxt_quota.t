:INPUT,FORWARD,OUTPUT
-m quota --quota 0;=;OK
# iptables-save shows wrong output
# ERROR: cannot find: iptables -I INPUT -m quota ! --quota 0)
#-m quota ! --quota 0;=;OK
-m quota --quota 18446744073709551615;=;OK
# ERROR: cannot find: iptables -I INPUT -m quota ! --quota 18446744073709551615
#-m quota ! --quota 18446744073709551615;=;OK
-m quota --quota 18446744073709551616;;FAIL
-m quota;;FAIL
