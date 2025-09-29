import sympy
import random

def get_private_key(y, g, p):
    """
    Alinea número 5:
    Ataque de força bruta, resolver (g^x mod p) até que o resultado seja o valor da chave pública (y)

    Args:
        y (integer): chave pública da sessão
        g (integer): parâmetro gerador
        p (integer): inteiro primo usado para gerar g

    Returns:
        integer: chave privada da sessão
    """
    
    # 1 < x < (q - 1) ==> x < p
    for x in range(p):
        
        #testar o valor atual de x
        tmp = pow(g,x,p)
        
        #valor de X encontrado
        if tmp == y:
            break
    
    return x