# SPDX-License-Identifier: GPL-2.0-only
all: encryption_priv.pem encryption_pub.txt sign_priv.pem sign_pub.txt

encryption_priv.pem:
	openssl ecparam -name prime256v1 -genkey -noout -out encryption_priv.pem

 encryption_pub.txt: encryption_priv.pem
	openssl pkey -in encryption_priv.pem -pubout -noout -text |./convert_to_hex.py > encryption_pub.txt

sign_priv.pem:
	openssl ecparam -name prime256v1 -genkey -noout -out sign_priv.pem

 sign_pub.txt: sign_priv.pem
	openssl pkey -in sign_priv.pem -pubout -noout -text |./convert_to_hex.py > sign_pub.txt
