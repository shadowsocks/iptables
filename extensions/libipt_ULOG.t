:INPUT,FORWARD,OUTPUT
-j ULOG --ulog-nlgroup 1;-j ULOG;OK
-j ULOG --ulog-nlgroup 32;=;OK
-j ULOG --ulog-nlgroup 33;;FAIL
-j ULOG --ulog-nlgroup 0;;FAIL
-j ULOG --ulog-cprange 1;=;OK
-j ULOG --ulog-cprange 4294967295;=;OK
# This below outputs 0 in iptables-save
# ERROR: should fail: iptables -A INPUT -j ULOG --ulog-cprange 4294967296
#-j ULOG --ulog-cprange 4294967296;;FAIL
# supports up to 31 characters
-j ULOG --ulog-prefix xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;=;OK
# ERROR: should fail: iptables -A INPUT -j ULOG --ulog-prefix  xxxxxx [...]
#-j ULOG --ulog-prefix xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;;FAIL
-j ULOG --ulog-qthreshold 1;-j ULOG;OK
-j ULOG --ulog-qthreshold 0;;FAIL
-j ULOG --ulog-qthreshold 50;=;OK
-j ULOG --ulog-qthreshold 51;;FAIL
-j ULOG;=;OK
