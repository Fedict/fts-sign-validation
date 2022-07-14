
keytool -delete     -alias UTRoot -storepass 123456 -keystore test_truststore.p12
keytool -importcert -alias UTRoot -storepass 123456 -keystore test_truststore.p12 -file ..\..\..\..\..\testpki\target\root.p12
copy ..\..\..\..\..\testpki\target\citizen202207.crl ..\..\..\..\..\mintest\test_fps\static\
copy ..\..\..\..\..\testpki\target\citizen_nonrep.p12 ..\..\test\resources\
