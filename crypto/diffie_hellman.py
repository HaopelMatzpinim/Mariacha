import math

P = 23
G = 5

def modulo_group_pow(num):
    return math.pow(G,num) % P;
