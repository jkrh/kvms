# SPDX-License-Identifier: GPL-2.0-only

all: signature_pub.h encryption_priv.h encryption_pub.pem

signature_pub.h:
	openssl pkey -in signature_priv.pem -text -noout | ./convert_to_h.py pub signature_pub > signature_pub.h

encryption_pub.pem:
	openssl pkey -in encryption_priv.pem -pubout -out encryption_pub.pem

encryption_priv.h:
	openssl pkey -in encryption_priv.pem --text -noout | ./convert_to_h.py priv encryption_priv > encryption_priv.h

.PHONY: all
