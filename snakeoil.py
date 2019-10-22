import base64
import codecs
import imghdr
infile = open("evidence.txt", "r")
data = infile.read()
rot13 = codecs.encode(data, 'rot13')
reversed_str = rot13[::-1]
b64 = base64.b64decode(reversed_str)
image_type = imghdr.what("evidence.txt", b64)
f = open("output." + image_type, "w+")
f.write(b64)
