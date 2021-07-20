
import base64
import ecdsa


for i in range(10):
    sk_filename = "sk%s" % i
    sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    open("users/%s.pem" % sk_filename, "w").write(bytes.decode(sk.to_pem()))
