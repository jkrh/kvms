# SPDX-License-Identifier: GPL-2.0-only
guest_image_priv.pem:
	openssl ecparam -name prime256v1 -genkey -noout -out  guest_image_priv.pem
	openssl pkey -in guest_image_priv.pem -pubout -text -noout | ./convert_to_h.py  > guest_image_pub.h

guest_image_pub.h: guest_image_priv.pem
