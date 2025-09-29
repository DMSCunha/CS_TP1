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
    
    #caso não haja mensagem
    if n == 0:
        raise ValueError("Message is empty (0)")
    
    while True:
        #dois primos aleatórios, de acordo com documentação do DSA, p tem 3072 bits e q tem 160 bits
        #aqui são usados 16
        p = sympy.randprime(1, 2**16)
        q = sympy.randprime(1, 2**16)
        
        #se p-1 for múltiplo de q
        if (p - 1) % q == 0 :
            print(f"[DEBUG]: p = {p} and q = {q}")
            break
    
    while True:
        #cálculo do g
        # // é necessário para a divisão por inteiros, se não pow() não funciona mesmo o resultado sendo um int
        g = pow(n, (p - 1)//q, p)
        
        #caso seja 1
        if g != 1:
            break
    
    return (p, q, g)

def get_skeys(p, q, g):
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
    
    y = pow(g, x, p)
    
    return (x,y)

