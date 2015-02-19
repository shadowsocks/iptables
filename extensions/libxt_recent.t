:INPUT,FORWARD,OUTPUT
-m recent --set;=;OK
-m recent --rcheck --hitcount 8 --name foo --mask 255.255.255.255 --rsource;=;OK
-m recent --rcheck --hitcount 12 --name foo --mask 255.255.255.255 --rsource;=;OK
-m recent --update --rttl;=;OK
-m recent --set --rttl;=;FAIL
-m recent --rcheck --hitcount 999 --name foo --mask 255.255.255.255 --rsource;=;FAIL
