# generate secp256r1 curve EC key pair
# Note: openssl uses the X9.62 name prime256v1 to refer to curve secp256r1, so this will generate output
% openssl ecparam -genkey -name secp256r1 -out k.pem

# print private key and public key
% openssl ec -in k.pem -noout -text

Private-Key: (256 bit)
priv:
    11:b5:73:7c:f9:d9:3f:17:c0:cb:1a:84:65:5d:39:
    95:a0:28:24:09:7e:ff:a5:ed:d8:ee:26:38:1e:b5:
    d6:c3
pub:
    04:a0:15:32:a3:c0:90:00:53:de:60:fb:ef:ef:cc:
    a5:87:93:30:15:98:d3:08:b4:1e:6f:4e:36:4e:38:
    8c:27:11:be:f4:32:c5:99:14:8c:94:14:3d:4f:f4:
    6c:2c:b7:3e:3e:6a:41:d7:ee:f2:3c:04:7e:a1:1e:
    60:66:7d:e4:25
ASN1 OID: prime256v1
