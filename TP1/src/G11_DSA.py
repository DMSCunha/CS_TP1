#
#   Modulo que contém os metodos da assinatura digital DSA
#

import sympy
import random
#----------------------
def get_DSAparameters(n: int):
    """
    Alinea número 1:
    gerar os parâmetros de domínio (p,q,g).
    
    Condições do enunciado:
    No contexto deste trabalho, o tamanho da chave (n) é o número de bits de **q**.
    
    Constraints / objetivos:
    - **p** e **q** são primos;
    - **p - 1** é múltiplo de **q**;
    - **h**: um número inteiro aleatório entre **1 < h < p - 1**;
    - **g**: não pode ser 1.

    Args:
        n (integer): tamanho da chave em bits.

    Returns:
        p, q, g: conjunto necessário de parâmetros para o algoritmo DSA.
    """

    # q random
    q = sympy.randprime(2**(n-1), 2**n)
    # Encontrar p = k(nr inteiro) *q + 1
    k_min = int(2**(n - 32)) #q aleatorio entre com (exemplo n=64) 2^64, logo k tem de ser no minimo 2^32
    k_max = int(2**(n - 1))
    for k in range(k_min, k_max):
        #cálculo do p 
        p = k * q + 1

        #se for primo
        if sympy.isprime(p):
            break
    else:
        raise ValueError("Could not find suitable p")

    while True:
        # Escolhido um inteiro h aleatoriamente, tal que 1 < h < p 1;
        h = random.randint(2, p - 1)
        
        #cálculo do g
        g = pow(h, (p - 1)//q, p) #é necessário // para que o resultado da divisão seja interpretado como um inteiro

        #caso seja 1
        if g != 1:
            break
    
    return p, q, g

def get_skeys(p: int, q: int, g: int):
    """
    Alinea número 2:
    Gerar a chave privada (x) e a chave pública da sessão a partir dos parâmetros de domínio (p,q,g).

    Constraints/objetivos:
    - x: chave privada da sessão tem de ser um número inteiro tal que : **1 < x < q - 1**

    Args:
        p (integer): número inteiro primo usado para gerar g
        q (integer): número inteiro primo usado para gerar g
        g (integer): parâmetro gerador

    Returns:
        x, y: chave privada e chave pública
    """
    
    #gerar a chave privada x, número interio aleatório maior que 1 e menor que q-1
    x = random.randint(2,q-1)
    
    #gerar a chave pública y através da privada x e dos parametros g e p
    y = pow(g, x, p)
    
    return x,y

""""
 Implemente a função dsa_sign(message, p, q, g, x) com argumentos a mensagem, os parâmetros
de domínio, a chave privada de sessão e retorno uma assinatura (r,s) para a mensagem (todas as
variáveis de tipo int).
 """
def dsa_sign(message: int, p: int, q: int, g: int, x: int):
    H_m = message  # hash da mensagem, simplificado para ser a mesma
    while True:
        # 1 < k < q-1
        k = random.randint(1, q - 1)

        # 2 r = (g^k mod p) mod q
        r = pow(g, k, p) % q

        # caso improvável de r ser 0
        if r == 0:
            continue  # repetir

        # 3 s = k^(-1) * (H(m) + x*r) mod q
        k_inv = pow(k, -1, q)  # inverso multilicativo de k módulo q
        s = (k_inv * (H_m + x * r)) % q

        # caso improvável de s ser 0
        if s == 0:
            continue  # repetir
        
        return r, s

"""
 Implemente a função dsa_verify(message, signature, p, q, g, y) com argumentos a mensa
gem, a assinatura, os parâmetros de domínio e chave pública de sessão (tipo int), e retorno True ou False.
"""

def dsa_verify(message: int, signature: tuple[int, int], p: int, q: int, g: int, y: int):
    r = signature[0]
    s = signature[1]

    # 1
    if not (0 < r < q) or not (0 < s < q):
        return False

    # 2
    w = pow(s, -1, q)
    # 3
    u1 = (message * w) % q
    # 4
    u2 = (r * w) % q
    # 5
    v = (pow(g, u1, p) * pow(y, u2, p)) %p % q

    # 6
    return v == r