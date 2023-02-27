import time
import hashlib
from tinyec.ec import SubGroup, Curve
from tinyec import registry
import secrets
import random

NUMBER_OF_NODES = 15
node_id = random.randint(1, NUMBER_OF_NODES)
## Hash algorithms
# hashAlgorithmsAvailable = hashlib.algorithms_available
# print(hashAlgorithmsAvailable)
hash1 = hashlib.blake2b()
hash2 = hashlib.md5()
hash3 = hashlib.sha256()

## Tiny EC
curve = registry.get_curve('secp192r1')
## 1. Setup phase
s = secrets.randbelow(curve.field.n)
Ppub = s * curve.g

## 2. Extract-Partial-Private-Key
r = secrets.randbelow(curve.field.n)
R = r * curve.g
inputText1 = str(node_id) + str(R.x) + str(R.y) + str(Ppub.x) + str(Ppub.y)
hash1.update(inputText1.encode())
h1 = int(hash1.hexdigest(), 16)
d = (r + h1 * s)
## KGC sends (R, d) to the user
## Verification equation
lhs = d * curve.g
rhs = h1 * Ppub + R
# print(lhs.x, lhs.y)
# print(rhs.x, rhs.y)

## 3. Set-Secret-Value
x = secrets.randbelow(curve.field.n)

X = x * curve.g

## 4. Set-Public-Key
## User sets Public Key -> (R, X)

## 5. Set-Private-Key
## User sets Private Key -> (d, x)

## 6. Sign
start = time.time()
u = secrets.randbelow(curve.field.n)
U = u * curve.g
inputText2 = str(node_id) + str(X.x) + str(X.y) + str(Ppub.x) + str(Ppub.y)
hash2.update(inputText2.encode())
h2 = int(hash2.hexdigest(), 16)
m = 'Hello this is Rhithick'
inputText3 = str(node_id) + m + str(R.x) + str(R.y) + str(X.x) + str(X.y) + str(U.x) + str(U.y)
hash3.update(inputText3.encode())
h3 = int(hash3.hexdigest(), 16)
v = d + h3 * u + h2 * x
end = time.time()
print(end-start)
# print('{0:.10f}'.format(tow))
## Signature (U, v)

## 7. Verify
lhs = v * curve.g
rhs = R + h1 * Ppub + h2 * X + h3 * U
print(lhs.x, lhs.y)
print(rhs.x, rhs.y)