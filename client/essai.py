# from pynode import Node, get_all_nodes, create_tree, Tree, get_value_leaves, get_node
from mysike import step, Complex, createSS, bass, test, multiply, addition


eA = 4
eB = 3
p = (2**eA)*(3**eB) - 1
A = Complex(423+329j)
kA = 9
kB = 2


PA = [Complex(122 + 163j), Complex(5 + 14j)]
QA = [Complex(252 + 54j), Complex(295 + 136j)]
PB = [Complex(322 + 136j), Complex(85 + 291j)]
QB = [Complex(74 + 53j), Complex(258 + 401j)]

test(A, PA, QA, PB, QB, kA, kB, eA, eB)

# PPB = [Complex(408 + 155j), Complex(1 + 366j)]
# QQB = [Complex(367 + 122j), Complex(358 + 189j)]

# PPA = [Complex(139 + 64j), Complex(135 + 66j)]
# QQA = [Complex(148 + 72j), Complex(159 + 378j)]

# TR = [Complex(27 + 245j), Complex(0)]

# Aa = Complex(132 + 275j)
# F = addition(A, PPA, TR, p)

# print('F = ', F)

# print('*********')
# R = multiply(Aa, F, kA, p)
# print(R)
# RR = addition(Aa, PPA, R, p)
# print(RR)
