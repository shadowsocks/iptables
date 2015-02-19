:INPUT,FORWARD,OUTPUT
-j IDLETIMER --timeout;;FAIL
-j IDLETIMER --timeout 42;;FAIL
-j IDLETIMER --timeout 42 --label foo;=;OK
