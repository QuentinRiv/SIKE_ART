from appli import settings
import numpy as np
from numpy import random
import sys
from .x25519 import base_point_mult, multscalar
from time import sleep


class Complex(object):
    def __init__(self, re, im=0):
        if not isinstance(re, list):
            if isinstance(re, complex):
                self.re = int(re.real % p)
                self.im = int(re.imag % p)
            else:
                self.re = int(re % p)
                self.im = int(im % p)
        else:
            for elem in re:
                Complex(elem)

    def __str__(self):
        return "{} + {}j".format(self.re, self.im)

    def __repr__(self):
        return "{} + {}j".format(self.re, self.im)

    def __add__(self, other):
        if not isinstance(other, Complex):
            other = Complex(other)
        return Complex(self.re + other.re, self.im + other.im)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if not isinstance(other, Complex):
            other = Complex(other)
        return Complex(self.re - other.re, self.im - other.im)

    def __rsub__(self, other):
        return -self.__sub__(other)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __mul__(self, other):
        if isinstance(other, Complex):
            ab0 = self.re*other.re
            ab1 = self.im*other.im
            c = (self.re+self.im)*(other.re+other.im)
            return Complex(ab0-ab1, c-ab0-ab1)
        elif isinstance(other, int):
            return Complex(self.re*other, self.im*other)

    def __neg__(self):
        return Complex(-self.re, -self.im)

    def __eq__(self, other):
        return self.re == other.re and self.im == other.im

    def __ne__(self, other):    # Not equel ( != )
        return not self.__eq__(other)

    def __pow__(self, expo):
        # If it's a real number, we just use the already
        # existing function pow
        if self.im == 0:
            return Complex(pow(self.re, expo, p))
        else:
            return Cpower(self, expo, p)

    def __mod__(self, p):
        return Complex(self.re % p, self.im % p)

    def conj(self):
        return Complex(self.re, -self.im)

    def inverse(self):
        num = self.conj()
        deno = (self*(self.conj())).re
        try:
            if sys.version_info[1] < 8:
                raise Exception("It would be better to have Python 3.8+")
                # inv = pow(deno, -1, p)
            else:
                inv = pow(deno, -1, p)
        except Exception:
            raise Exception("{} is not invertible in mod {}".format(deno, p))
        inv = Complex(inv)
        return num*inv

    def tocomplex(self):
        return self.re + 1j*self.im

    def sqrt_root(self):
        sqrt_r = sqrtcomp(self.tocomplex(), p)
        return Complex(sqrt_r)


def convert_Complex(liste):
    liste_Complex = []
    for elem in liste:
        if isinstance(elem, list):
            liste_Complex += [convert_Complex(elem)]
        else:
            liste_Complex += [Complex(elem)]
    return liste_Complex


def jinv(A, p):
    num = 256*(A**2 - 3)**3
    deno = A**2 - 4
    inv = deno.inverse()
    return num*inv


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def testoncurve(A, P, p):
    [x, y] = P

    left = y**2
    right = x**3 + A*x**2 + x
    return left == right


def double(A, P, p):
    [x, y] = P
    num = 3*(x**2) + 2*A*x + 1
    deno = 2*y
    lam = num*deno.inverse()
    Xr = lam**2 - A - 2*x
    Yr = lam*(x - Xr) - y
    return [Xr, Yr]


def triple(A, P, p):
    double_P = double(A, P, p)
    triple_P = addition(A, P, double_P, p)
    return triple_P


def findY(A, x, p):
    right = x**3 + A*x**2 + x
    if (right.re == 0) and (right.im == 0):
        return 0 + 0j
    sqrtc = sqrtcomp(right, p)
    if sqrtc == Complex(-1):
        raise Exception("Non Y could be found")
    return sqrtc


def nouvA(alpha, A, p, side):
    if side == "initiator":
        return 2*(1 - 2*alpha**2)
    else:
        return (A*alpha - 6*(alpha**2) + 6)*alpha


def addition(A, P, Q, p):
    [x1, y1] = P
    [x2, y2] = Q
    num = y2 - y1
    deno = x2 - x1
    inv = deno.inverse()
    lam = num*inv
    Xr = lam**2 - A - x1 - x2
    Yr = lam*(x1 - Xr) - y1
    return [Xr, Yr]


def multiply(A, P, k, p):
    k = int(k)

    if k == 0:
        return [Complex(0), Complex(0)]

    arr = np.array(list(np.binary_repr(k))).astype(np.int8)

    aPoint = []
    R = P
    if arr[-1] == 1:
        aPoint += [R]
    arr = arr[:-1]
    for i, b in enumerate(arr[::-1]):
        R = double(A, R, p)

        if b == 1:
            aPoint += [R]
    Q = aPoint[0]
    for i, T in enumerate(aPoint[1:]):
        Q = addition(A, Q, T, p)

    return Q


def Cpower(x, y, p):

    res = Complex(1)  # Initialize result
    x = x % p  # Update x if it is more
    # than or equal to p

    while y > 0:

        # If y is odd, multiply x with result
        if y & 1:
            res = (x * res) % p

        # y must be even now
        y = y >> 1  # y = y/2
        x = (x * x) % p

    return res


def legendre(a, p):
    return pow(a, int((p-1)/2), p)


def squareRoot(n, p):

    if n == 0:
        return 0

    if legendre(n % p, p) != 1:
        return Exception("Square root of doesn't exist")

    if (p % 4) != 3:
        raise Exception("p is not 3 mod 4")

    # Try "+(n^((p + 1)/4))"
    n = n % p
    x = pow(n, (p + 1) // 4, p)
    if ((x * x) % p) == n:
        return int(x)

    # Try "-(n ^ ((p + 1)/4))"
    x = p - x
    if ((x * x) % p) == n:
        return int(x)

    # If none of the above two work, then
    # square root doesn't exist
    raise Exception("Square root of doesn't exist")


# OK
def sqrtcomp(z, p):
    if (p % 4) != 3:
        return "Problem : p != 3 mod 4"

    a = z.re
    b = z.im

    if legendre((a**2 % p) + (b**2 % p), p) != 1:
        return -1

    de = squareRoot((a**2 % p) + (b**2 % p), p)

    try:
        tr = (a + de) % p
        frac = tr*modinv(2, p)
        x = squareRoot(frac, p) % p
        if x == 0:
            y = squareRoot(-a % p, p) % p
        else:
            y = b*modinv(2*x, p) % p
        return Complex(x, y)
    except Exception:
        try:
            tr = (a - de) % p
            frac = tr*modinv(2, p)
            x = squareRoot(frac, p) % p
            if x == 0:
                y = squareRoot(-a % p, p) % p
            else:
                y = b*modinv(2*x, p) % p
            return Complex(-x, -y)
        except Exception:
            raise Exception("Impossible to find a root for " + str(z))


def phi(alpha, P, p, side):
    [x, y] = P

    xAlph = alpha*x
    x2 = x**2
    xmAlph = x - alpha
    if side == "initiator":
        numX = x*(xAlph - 1)
        denoX = xmAlph
    elif side == "receiver":
        numX = x*((xAlph - 1)**2)
        denoX = xmAlph**2
    invX = denoX.inverse()
    X = numX*invX

    if side == "initiator":
        numY = x2*alpha - 2*x*(alpha**2) + alpha
        denoY = xmAlph**2
    elif side == "receiver":
        numY = (x*alpha - 1)*(x2*alpha - 3*x*(alpha**2) + x + alpha)
        denoY = xmAlph**3
    invY = denoY.inverse()
    try:
        r = sqrtcomp(alpha, p)
    except Exception:
        raise Exception("Problème pour la racine d'alpha...")
    if side == "initiator":
        Y = numY*invY
        Y = y*Y
        Y = r*Y
    else:
        Y = numY*invY
        Y = y*Y
        Y = Y*alpha
    return [X, Y]


def step(n, A, P, Q, PP, QQ, k, side, show=False):
    # print("\n************", side, "***********")

    SS = None

    if side == "initiator":
        o = [2**i for i in range(n)][::-1]
    elif side == "receiver":
        o = [3**i for i in range(n)][::-1]
    else:
        return "Error !"
    # o = [2**i for i in range(n)][::-1]

    for ind, i in enumerate(o):
        # print("\nPhi", ind)
        # print('A = ', A)
        # jA = jinv(A, p)
        # print("Invariant de ", A, ":", jA)

        if i == o[0]:
            Y = multiply(A, Q, k, p)
            S = addition(A, P, Y, p)
            # print("\nSA = ", P, "+", k, "*", Q)
            # print("= {} + {}".format(P, Y))
        else:
            S = SS

        # print("S = ", S, "    ==> ord(S) =", order(A, S, p, side))

        SS = multiply(A, S, i, p)
        # print("[", i, "]SA =", SS)
        # print("Ordre = {}".format(order(A, SS, p, side)))
        A = nouvA(SS[0], A, p, side)
        # print('Nouveau A :', A)
        jAA = jinv(A, p)
        # print("Nouveau A = ", A, "  ==>  j(E) =", jAA)

        PP = phi(SS[0], PP, p, side)
        QQ = phi(SS[0], QQ, p, side)
        # print("\nP =", PP, "- Q =", QQ)

        if i != 1:
            SS = phi(SS[0], S, p, side)
        # print("Nouveau SA =", SS)

        # input()

    if show:
        print("Invariant final : ", jAA)
        print("Return :", [A, PP, QQ])
    return [[A, PP, QQ], jAA]


def generatePoint(A, p):
    u = Complex(4, 1)
    r = Complex(random.randint(1, p), random.randint(1, p))
    try:
        v = -A*(1 + u*(r**2)).inverse()
        Py = findY(A, v, p)
    except Exception:
        v = A*(1 + u*(r**2) - A).inverse()
        Py = findY(A, v, p)
    testoncurve(A, [v, Py], p)
    # print('Point :', [v, Py])
    return [v, Py]


def order(A, P, p, side):

    PP = P
    if side == "initiator":
        for i in range(1, 20):
            try:
                PP = double(A, PP, p)
            except Exception:
                return 2**i

    elif side == "receiver":
        for i in range(1, 10):
            try:
                PP = triple(A, PP, p)
            except Exception:
                return 3**i


def bass(A, eA, eB, p, side):
    for i in range(10):
        P = generatePoint(A, p)
        # print('P = ', P)
        # print('Sur la courbe :', testoncurve(A, P, p))
        if side == "initiator":
            PP = multiply(A, P, 3**eB, p)
        else:
            PP = multiply(A, P, 2**eA, p)
        # print('PP = ', PP)
        u = order(A, PP, p, side)
        # print('Ordre = 2^{}'.format(u))
        if (u == 2**eA) or (u == 3**eB):
            # print("Trouvé !")
            return PP


def test(A, PA, QA, PB, QB, kA, kB, eA, eB):
    resultatA = step(eA, A, PA, QA, PB, QB, kA, "initiator")
    resultatB = step(eB, A, PB, QB, PA, QA, kB, "receiver")

    [nA, nPA, nQA] = resultatA[0]
    [nB, nPB, nQB] = resultatB[0]

    resultatA = step(eA, nB, nPB, nQB, PB, QB, kA, "initiator")
    resultatB = step(eB, nA, nPA, nQA, PA, QA, kB, "receiver")

    if resultatA[1] != resultatB[1]:
        print("\n**********FAUUUUUUUUX**********")
        return 1
    else:
        print("\n\nYEEEEEEEEEEES!!")
        return 1


def compute_pk(secretK, side, method="sike27"):
    if method == "sike27":
        return SIKE_compute_pk(secretK, side)
    elif method == "ecdh" or method == "SIKE751":
        if method == "SIKE751":
            sleep(0.00487)

        if secretK == 0:
            secretK = 1
        if isinstance(secretK, int):
            secretK = secretK.to_bytes(32, 'big')

        return base_point_mult(secretK)


def SIKE_compute_pk(secretK, side, show=False):
    if side == "initiator":
        return step(eA, A, PA, QA, PB, QB, secretK, "initiator", show)[0]
    elif side == "receiver":
        return step(eB, A, PB, QB, PA, QA, secretK, "receiver", show)[0]


def createSS(publicK, secretK, method="sike27", side=""):
    if method == "sike27":
        return SIKE_createSS(publicK, secretK, side)
    elif method == "ecdh" or method == "SIKE751":
        if method == "SIKE751":
            sleep(0.00487)  # Difference of delaying time
        if isinstance(secretK, int):
            secretK = secretK.to_bytes(32, 'big')
        return multscalar(secretK, publicK)


def SIKE_createSS(publicK, secretK, side, show=False):
    [A, P, Q] = publicK
    # print('A =', A, ' - type :', type(A))

    SS = None

    n = eA if side == 'initiator' else eB

    if side == "initiator":
        o = [2**i for i in range(n)][::-1]
    elif side == "receiver":
        o = [3**i for i in range(n)][::-1]
    else:
        return "Error !"

    for ind, i in enumerate(o):
        # jA = jinv(A, p)

        if i == o[0]:
            Y = multiply(A, Q, secretK, p)
            S = addition(A, P, Y, p)
        else:
            S = SS

        SS = multiply(A, S, i, p)
        A = nouvA(SS[0], A, p, side)
        jA = jinv(A, p)
        # print('jA :', jA)

        if i != 1:
            SS = phi(SS[0], S, p, side)

    if show:
        print("Invariant final : ", jA)
    return jA


eA = 15
eB = 8
p = (2**eA)*(3**eB) - 1
A = Complex(6)

PA = [Complex(86376864 + 170171585j), Complex(127821438 + 16383740j)]
QA = [Complex(161217342 + 99659163j), Complex(125060903 + 201406548j)]
PB = [Complex(187678265 + 129137657j), Complex(162754188 + 159732437j)]
QB = [Complex(64400912 + 212570136j), Complex(105210572 + 213112517j)]

server_address = settings.SERVER_ADDRESS
# server_address = "https://serverart.herokuapp.com/"


# If someone wants to play and make some test :

# eA = 4
# eB = 3
# p = (2**eA)*(3**eB) - 1
# A = Complex(423+329j)


# PA = [Complex(248+100j), Complex(199+304j)]
# QA = [Complex(394+426j), Complex(79+51j)]
# PB = [Complex(275+358j), Complex(104+410j)]
# QB = [Complex(185+20j), Complex(239+281j)]
