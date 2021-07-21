
import base64
import ecdsa


for i in range(10):
    sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    open("users/sk%s.pem" % i, "w").write(bytes.decode(sk.to_pem()))
