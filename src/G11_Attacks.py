#
#   Módulo de ataques ao DSA
#

def get_private_key(y: int, g: int, p: int):
    """
    Alinea número 5:
    Ataque de força bruta, resolver (g^x mod p) até que o resultado seja o valor da chave pública (y)

    Args:
        y (integer): chave pública da sessão
        g (integer): parâmetro gerador
        p (integer): número inteiro primo usado para gerar g

    Returns:
        integer: chave privada da sessão
    """
    
    # 1 < x < (q - 1) ==> x < p
    for x in range(p):
        
        #testar o valor atual de x
        #valor de X encontrado
        if pow(g,x,p) == y:
            break
    
    return x

def dsa_sign_k_rigged(message: int, p: int, q: int, g: int, x: int):
    H_m = message  # hash da mensagem, simplificado para ser a mesma
    while True:
        # K hardcoded
        k = 16

        # 2 r = (g^k mod p) mod q
        r = pow(g, k, p) % q

        # caso improvável de r ser 0
        if r == 0:
            continue  # repetir
        
        # 3 s = k^(-1) * (H(m) + x*r) mod q
        k_inv = pow(k, -1, q)  # inverso multiplicativo de k módulo q
        s = (k_inv * (H_m + x * r)) % q

        # caso improvável de s ser 0
        if s == 0:
            continue  # repetir
        
        return r, s

def get_private_key_k_rigged(s1: tuple[int, int], s2: tuple[int, int], q: int, H_m1: int, H_m2: int):
    r1, s1 = s1
    r2, s2 = s2

    return ((s2 * H_m1 - s1 * H_m2) * pow(r1 * (s1 - s2), -1, q)) % q
