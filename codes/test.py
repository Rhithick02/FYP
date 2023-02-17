from tinyec.ec import SubGroup, Curve
import hashlib
hash2 = hashlib.md5()
hash2.update('Bi I am Vivek'.encode())
print(hash2.hexdigest())
# field = SubGroup(p=17, g=(8, 3), n=18, h=1)
# curve = Curve(a=0, b=7, field=field, name='p1707')
# print('curve:', curve)

# for k in range(0, 25):
#     p = k * curve.g
#     print(f"{k} * G = ({p.x}, {p.y})")