import sympy
import random

def get_DSAparamenters(n: int):
    """
    Alinea número 1:
    gerar os parâmetros de domínio (p,q,g).
    
    Assumptions:
    No contexto desta alinea, o tamanho da mensagem (n) é o **h**.
    **h** é o número inteiro aleatóriamente escolhido segundo a documentação do DSA.
    
    Constraints / objetivos:
    - **p** e **q** são primos;
    - **n** e **q** são primos;
    - **p -1** é múltiplo de **q**;
    - **n** tem de ser um número entre **1 < n < p -1**;
    - **g** gerado não pode ser 1.

    Args:
        n (integer): tamanho da mensagem.

    Returns:
        tuple (p,q,g): conjunto necessário de parâmetros para o algoritmo DSA.
    """

    if n < 65:
        raise ValueError("Size n must be at least 64 bits, otherwise not safe")

    # q random
    q = sympy.randprime(2**(n-1), 2**n)
    # Encontrar p = k(nr inteiro) *q + 1
    k_min = 2**(n - 32) #q aleatorio entre com (exemplo n=64) 2^64, logo k tem de ser no minimo 2^32
    k_max = 2**(n - 1)
    for k in range(k_min, k_max):
        p = k * q + 1
        if sympy.isprime(p):
            break
    else:
        raise ValueError("Could not find suitable p")

    print(f"[DEBUG] Random prime numbers : p = {p} and q = {q}")

    while True:
        #cálculo do g
        # Escolhido um inteiro h aleatoriamente, tal que 1 < h < p 1;
        h = random.randint(2, p - 1) # 1 < h < p-1
        g = pow(h, (p - 1)//q, p) # // preciso para divisão inteira

        #caso seja 1
        if g != 1:
            break
    
    print(f"[DEBUG] Generated g = {g}")
    
    return p, q, g

def get_skeys(p: int, q: int, g: int):
    """
    Alinea número 2:
    Gerar a chave privada (x) e a chave pública da sessão a partir dos parâmetros de domínio (p,q,g).

    Args:
        p (integer): inteiro primo usado para gerar g
        q (integer): inteiro primo usado para gerar g
        g (integer): parâmetro gerador

    Returns:
        tuple (x,y): chave privada e chave pública
    """
    
    x = random.randint(1,q-1)
    print(f"[DEBUG] Randomize private session key x = {x}")
    
    y = pow(g, x, p)
    print(f"[DEBUG] Generated public session key y = {y}")
    
    return x,y
