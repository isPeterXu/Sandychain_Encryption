from charm.toolbox.msp import MSP
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
# from msp import MSP
import hashlib

# debug = False

group = PairingGroup('MNT224')


# def __init__(self, group_obj, assump_size, k, verbose=False):
#         ABEnc.__init__(self)
#         self.group = group_obj
#         self.assump_size = assump_size  # size of linear assumption, at least 2
#         self.util = MSP(self.group, verbose)
#         self.k = k
#         self.index = k
#         self.i = 5
#         self.j = 5  # we assume i = j, equals to identity-based encryption.
#         self.msk = {}
#         self.mpk = {}
#         self.pk = None
#         self.sk = None
#         self.sk_delta = None
#         self.ID_i = None
#         self.ID_j = None
#         self.I = []
#         for i in range(self.k):
#             self.I.append(self.group.random(ZR))


def setup(k, ii, jj):
    """
    Generates public key and master secret key.
    """

    if debug:
        print('\nSetup algorithm:\n')

    # (sk, pk)
    h = group.random(G2)
    sk = group.random(ZR)
    pk = h ** sk

    # (msk, mpk)
    g = group.random(G1)
    a0 = group.random(ZR)
    a1 = group.random(ZR)
    b0 = group.random(ZR)
    b1 = group.random(ZR)
    alpha = group.random(ZR)
    beta = group.random(ZR)
    d0 = group.random(ZR)
    d1 = group.random(ZR)
    d2 = group.random(ZR)
    g_d1 = g ** d0
    g_d2 = g ** d1
    g_d3 = g ** d2
    Z = []  # {z1,...,zk}
    G = []  # {g1,...,gk}
    H = []  # {h1,...,hk}
    GZ = []  # {g_z1,...,g_zk}
    HZ = []  # {h_z1,...,h_zk}
    for i in range(k):
        Z.append(group.random(ZR))
        G.append(group.random(G1))
        H.append(group.random(G2))
        GZ.append(g ** Z[i])
        HZ.append(h ** Z[i])

    e_gh = pair(g, h)
    H1 = h ** a0
    H2 = h ** a1
    T1 = e_gh ** (d0 * a0 + d2 / alpha)
    T2 = e_gh ** (d1 * a1 + d2 / alpha)
    g_alpha = g ** alpha
    d = d0 + d1 + d2
    h_d_alpha = h ** (d / alpha)
    h_1_alpha = h ** (1 / alpha)
    h_beta_alpha = h ** (beta / alpha)

    I = []
    for i in range(k):
        I.append(group.random(ZR))
    ID_i = 1
    for i in range(ii):
        g_k = GZ[k - i - 1]
        ID_i *= g_k ** I[i]
    ID_i *= g
    ID_j = 1
    for j in range(jj):
        h_k = HZ[k - j - 1]
        ID_j *= h_k ** I[j]
    ID_j *= h

    msk = {'a0': a0, 'a1': a1, 'b0': b0, 'b1': b1, 'alpha': alpha, 'beta': beta, 'd0': d0, 'd1': d1, 'd2': d2,
           'g_d1': g_d1, 'g_d2': g_d2, 'g_d3': g_d3, 'Z': Z}
    mpk = {'g': g, 'h': h, 'H1': H1, 'H2': H2, 'T1': T1, 'T2': T2, 'GZ': GZ, 'HZ': HZ, 'g_alpha': g_alpha,
           'h_d_alpha': h_d_alpha, 'h_1_alpha': h_1_alpha, 'h_beta_alpha': h_beta_alpha}

    return sk, pk, msk, mpk, ID_i, ID_j


def keygen(sk, msk, mpk, attr_list, assump_size, ii, ID_i):
    """
    Generate a key for a list of attributes.
    """

    if debug:
        print('\nKey generation algorithm:\n')

    # msk = msk
    # mpk = mpk
    # sk = sk
    # pk = pk
    g = mpk['g']
    h = mpk['h']
    alpha = msk['alpha']
    x = sk
    d = msk['d0'] + msk['d1'] + msk['d2']
    R = group.random(ZR)
    r1 = group.random(ZR)
    r2 = group.random(ZR)
    r = r1 + r2
    h_b1_r1 = h ** (msk['b0'] * r1)
    h_b2_r2 = h ** (msk['b1'] * r2)
    h_r1_r2_alpha = h ** ((r1 + r2) / alpha)
    g_1_alpha = g ** (1 / alpha)
    g_r_alpha = g ** (r / alpha)
    g_R = g ** R
    sk0 = {'h_b1_r1': h_b1_r1, 'h_b2_r2': h_b2_r2, 'h_r1_r2_alpha': h_r1_r2_alpha, 'g_1_alpha': g_1_alpha,
           'g_r_alpha': g_r_alpha, 'g_R': g_R}
    SK = {}  # SK = {[sk_y_1, sk_y_2]} sk_y_t
    sk_prime = []

    for attr in attr_list:
        sigma_y = group.random(ZR)
        key = []
        for t in range(assump_size):
            input_for_hash1 = attr + str(0) + str(t)
            input_for_hash2 = attr + str(1) + str(t)
            input_for_hash3 = attr + str(2) + str(t)
            a_t = 'a' + str(t)
            sk_y_t = group.hash(input_for_hash1, G1) ** (msk['b0'] * r1 / msk[a_t]) * group.hash(
                input_for_hash2, G1) ** (msk['b1'] * r2 / msk[a_t]) * group.hash(input_for_hash3, G1) ** (
                             (r1 + r2) / (alpha * msk[a_t])) * g ** (sigma_y / (alpha * msk[a_t]))
            key.append(sk_y_t)
        key.append(g ** (-sigma_y))
        SK[attr] = key

    sigma_prime = group.random(ZR)
    for t in range(assump_size):
        input_for_hash1 = "010" + str(t)
        input_for_hash2 = "011" + str(t)
        input_for_hash3 = "012" + str(t)
        a_t = 'a' + str(t)
        d_t = 'd' + str(t)
        sk_t = g ** msk[d_t] * group.hash(input_for_hash1, G1) ** (
                msk['b0'] * r1 / msk[a_t]) * group.hash(input_for_hash2, G1) ** (
                       msk['b1'] * r2 / msk[a_t]) * group.hash(input_for_hash3, G1) ** (
                       (r1 + r2) / (alpha * msk[a_t])) * g ** (sigma_prime / (alpha * msk[a_t]))
        sk_prime.append(sk_t)
    sk_prime.append(g ** msk['d2'] * g ** (-sigma_prime))

    sk1 = g ** d * ID_i ** (alpha * r) * g ** (msk['beta'] * R)

    sk2 = [None] * ((ii - 1) * 2)
    for i in range(ii - 1):
        g_k = mpk['GZ'][ii - 1 - i]
        sk2[i] = g_k ** (alpha * r)
        sk2[ii + i - 1] = g_k ** alpha

    ssk = {'sk0': sk0, 'sk_y_t': SK, 'sk_prime': sk_prime, 'sk1': sk1, 'sk2': sk2}
    sk_delta = {'x': x, 'ssk': ssk, 'attr_list': attr_list}

    return sk_delta


def hash(policy_str, msk, mpk, pk, assump_size, ID_j, verbose=False):
    # msk = self.msk
    # mpk = self.mpk
    # pk = self.pk
    h = mpk['h']
    g = mpk['g']
    util = MSP(group, verbose)
    policy = util.createPolicy(policy_str)
    mono_span_prog = util.convert_policy_to_msp(policy)
    num_cols = util.len_longest_row

    # step 1
    r = group.random(ZR)
    p = pk ** r

    # step 2
    R = group.random(ZR)
    sha256 = hashlib.new('sha256')
    sha256.update(group.serialize(R))
    hd = sha256.hexdigest()
    seed = str(hd)
    e = group.hash(seed, ZR)
    h_prime = h ** e

    # step 3
    m = group.random(ZR)
    b = p * h_prime ** m

    # step 4
    s = []
    sum = 0  # sum = s1 + s2
    for i in range(assump_size):
        rand = group.random(ZR)
        s.append(rand)
        sum += rand
    _sk = sum
    _vk = ID_j ** (msk['alpha'] * sum)

    # step 5
    ct0 = []
    H1 = mpk['H1']
    H2 = mpk['H2']
    ct0.append(H1 ** s[0])
    ct0.append(H2 ** s[1])
    ct0.append(h ** (sum / msk['alpha']))
    ct0.append(mpk['h_beta_alpha'] ** sum)

    # pre-compute hashes
    hash_table = []
    for j in range(num_cols):
        x = []
        input_for_hash1 = '0' + str(j + 1)
        for l in range(assump_size + 1):
            y = []
            input_for_hash2 = input_for_hash1 + str(l)
            for t in range(assump_size):
                input_for_hash3 = input_for_hash2 + str(t)
                hashed_value = group.hash(input_for_hash3, G1)
                y.append(hashed_value)
            x.append(y)
        hash_table.append(x)

    # compute C = ct_u_l
    C = {}
    for attr, row in mono_span_prog.items():
        ct = []
        attr_stripped = util.strip_index(attr)  # no need, re-use not allowed
        for l in range(assump_size + 1):
            prod = 1
            cols = len(row)
            for t in range(assump_size):
                input_for_hash = attr_stripped + str(l) + str(t)
                prod1 = group.hash(input_for_hash, G1)
                for j in range(cols):
                    prod1 *= (hash_table[j][l][t] ** row[j])
                prod *= (prod1 ** s[t])
            ct.append(prod)
        C[attr] = ct

    sha256 = hashlib.new('sha256')
    msg = mpk['T1'] ** s[0] * mpk['T2'] ** s[1]
    sha256.update(group.serialize(msg))
    hd = sha256.hexdigest()
    seed = str(hd)
    _ct = r * group.hash(seed, ZR)
    d = msk['d0'] + msk['d1'] + msk['d2']

    cpp = pair(g, h ** (d / msk['alpha'])) ** _sk
    seed = str(cpp)
    _ctp = R * group.hash(seed, ZR)
    _ct2p = _vk
    _ct3p = ID_j ** (sum)
    _ct4p = _vk ** (sum)
    _C = [ct0, C, _ct, _ctp, _ct2p, _ct3p, policy, _ct4p]

    # step 6
    c = h ** (_sk + R)
    esk = group.random(ZR)
    epk = pair(g, _vk) ** esk
    sigma = esk + _sk * group.hash(str(epk) + str(c))

    # step 7
    return m, p, h_prime, b, _C, c, epk, sigma


def verify(mpk, m, p, h_prime, b, C, c, epk, sigma):
    vk = C[4]  # get vk
    vk_s = C[7]  # get vk_s
    b_prime = p * h_prime ** m
    base = pair(mpk['g'], vk)
    base_sigma_prime = epk * pair(mpk['g'], vk_s) ** group.hash(str(epk) + str(c))

    if (b == b_prime and base ** sigma == base_sigma_prime):
        return 0
    else:
        return 1


def adapt(mpk, msk, sk_delta, m, h_prime, b, C, policy_str, assump_size, ID_j, pk, sk, verbose=False):
    util = MSP(group, verbose)
    m_prime = group.random(ZR)
    _m = group.random(ZR)
    g = mpk['g']
    h = mpk['h']
    d = msk['d0'] + msk['d1'] + msk['d2']
    alpha = msk['alpha']
    # mpk = self.mpk
    # msk = self.msk
    # sk_delta = sk_delta
    sk_prime = sk_delta['ssk']['sk_prime']
    # ID_i = self.ID_i

    policy = util.createPolicy(policy_str)
    mono_span_prog = util.convert_policy_to_msp(policy)
    num_cols = util.len_longest_row

    # step 2.(b)
    ctp = C[3]
    pair1 = pair(sk_delta['ssk']['sk1'], C[0][2])  # C[0][2] = ct0,3
    pair2 = pair(sk_delta['ssk']['sk0']['g_r_alpha'], C[4])  # C[4] = ct2p
    pair3 = pair(sk_delta['ssk']['sk0']['g_R'], C[0][3])  # C[0][3] = mpk['h_beta_alpha'] ** sum
    cpp = pair1 / (pair2 * pair3)
    seed = str(cpp)
    R = ctp / group.hash(seed, ZR)

    # step 3
    nodes = util.prune(C[6], sk_delta['attr_list'])  # C[6] = ctxt['policy'] get ciphertext policy
    if not nodes:
        print("Policy is not satisfied.")
        return None

    sk0_tmp = []
    sk0_tmp.append(sk_delta['ssk']['sk0']['h_b1_r1'])
    sk0_tmp.append(sk_delta['ssk']['sk0']['h_b2_r2'])
    sk0_tmp.append(sk_delta['ssk']['sk0']['h_r1_r2_alpha'])

    prod1_GT = 1
    prod2_GT = 1
    for i in range(assump_size + 1):
        prod_H = 1
        prod_G = 1
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = util.strip_index(attr)  # no need, re-use not allowed
            prod_H *= sk_delta['ssk']['sk_y_t'][attr_stripped][i]
            prod_G *= C[1][attr][i]  # C[1] = _C
        prod1_GT *= pair(sk_prime[i] * prod_H, C[0][i])
        prod2_GT *= pair(prod_G, sk0_tmp[i])
    Cp = -(prod2_GT / prod1_GT)

    sha256 = hashlib.new('sha256')
    sha256.update(group.serialize(Cp))
    x = sha256.hexdigest()
    seed = str(x)
    r_tmp = C[2] / group.hash(seed, ZR)  # C[2] = _ct

    # step 4
    s_prime = []
    sum_prime = 0  # sum = s1 + s2
    for i in range(assump_size):
        rand = group.random(ZR)
        s_prime.append(rand)
        sum_prime += rand

    _sk_prime = sum_prime
    _vk_prime = ID_j ** (msk['alpha'] * sum_prime)  # TODO add comment for ID_j

    # step 5
    sha256 = hashlib.new('sha256')
    sha256.update(group.serialize(R))
    hd = sha256.hexdigest()
    seed = str(hd)
    e = group.hash(seed, ZR)
    r_prime = r_tmp + (m - m_prime) * e / sk
    p_prime = pk ** r_prime

    # step 6
    ct0 = []
    H1 = mpk['H1']
    H2 = mpk['H2']
    ct0.append(H1 ** s_prime[0])
    ct0.append(H2 ** s_prime[1])
    ct0.append(h ** (sum_prime / msk['alpha']))
    ct0.append(mpk['h_beta_alpha'] ** sum_prime)

    # pre-compute hashes
    hash_table = []
    for j in range(num_cols):
        x = []
        input_for_hash1 = '0' + str(j + 1)
        for l in range(assump_size + 1):
            y = []
            input_for_hash2 = input_for_hash1 + str(l)
            for t in range(assump_size):
                input_for_hash3 = input_for_hash2 + str(t)
                hashed_value = group.hash(input_for_hash3, G1)
                y.append(hashed_value)
            x.append(y)
        hash_table.append(x)

    # compute C = ct_u_l
    C = {}
    for attr, row in mono_span_prog.items():
        ct = []
        attr_stripped = util.strip_index(attr)  # no need, re-use not allowed
        for l in range(assump_size + 1):
            prod = 1
            cols = len(row)
            for t in range(assump_size):
                input_for_hash = attr_stripped + str(l) + str(t)
                prod1 = group.hash(input_for_hash, G1)
                for j in range(cols):
                    prod1 *= (hash_table[j][l][t] ** row[j])
                prod *= (prod1 ** s_prime[t])
            ct.append(prod)
        C[attr] = ct

    # step 7
    sha256 = hashlib.new('sha256')
    msg = mpk['T1'] ** s_prime[0] * mpk['T2'] ** s_prime[1]
    sha256.update(group.serialize(msg))
    hd = sha256.hexdigest()
    seed = str(hd)
    _ct = r_prime * group.hash(seed, ZR)
    d = msk['d0'] + msk['d1'] + msk['d2']

    cpp = pair(g, h ** (d / msk['alpha'])) ** _sk_prime
    seed = str(cpp)
    _ctp = R * group.hash(seed, ZR)
    _ct2p = _vk_prime
    _ct3p = ID_j ** (sum_prime)
    _ct4p = _vk_prime ** (sum_prime)
    _C = [ct0, C, _ct, _ctp, _ct2p, _ct3p, policy, _ct4p]
    C_prime = _C

    c_prime = h ** (_sk_prime + R)
    esk_prime = group.random(ZR)
    epk_prime = pair(g, _vk_prime) ** esk_prime
    sigma_prime = esk_prime + _sk_prime * group.hash(str(epk_prime) + str(c_prime))

    return m_prime, p_prime, h_prime, b, C_prime, c_prime, epk_prime, sigma_prime


def judge(msk, mpk, m, p, h_prime, b, C, c, epk, sigma, m_prime, p_prime, C_prime, c_prime, epk_prime, sigma_prime,
          ID_i):
    # rs = 0
    alpha = msk['alpha']
    h = mpk['h']
    g = mpk['g']
    vk = C[4]
    vk_prime = C_prime[4]

    # step 1
    b0 = p * h_prime ** m
    b1 = p_prime * h_prime ** m_prime

    if (b == b0 and b == b1):
        rs = 0
    else:
        rs = 1

    # step 2
    vk_s = C[7]
    vk_s_prime = C_prime[7]
    base = pair(g, vk)
    base_prime = pair(g, vk_prime)
    base_sigma0 = epk * pair(g, vk_s) ** group.hash(str(epk) + str(c))
    base_sigma1 = epk_prime * pair(g, vk_s_prime) ** group.hash(str(epk_prime) + str(c_prime))
    if (base ** sigma == base_sigma0 and base_prime ** sigma_prime == base_sigma1):
        rs = 0
    else:
        rs = 1

    # step 3
    delta_sk = c_prime / c
    ct_0_3 = C[0][2]
    ct_0_3_prime = C_prime[0][2]
    if (ct_0_3_prime == ct_0_3 * delta_sk):
        rs = 0
    else:
        rs = 1

    # step 4
    pair1 = pair(g, vk ** (1 / (alpha * alpha)))
    pair2 = pair(ID_i, C[0][2])  # C[0][2] = ct_(0,3)
    if (pair1 == pair2):
        rs = 0
    else:
        rs = 1

    return rs


def TestExp(msk, mpk):
    mpk['g'] ** msk['a0']


if __name__ == '__main__':
    pass
    debug = True
    k = 10
    ii = 5
    jj = 5
    (sk, pk, msk, mpk, ID_i, ID_j) = setup(k, ii, jj)

    assump_size = 2
    attr_list = ['ONE', 'TWO', 'THREE']
    sk_delta = keygen(sk, msk, mpk, attr_list, assump_size, ii, ID_i)

    policy_str = '((ONE and THREE) and (TWO OR FOUR))'
    # m = None
    (m, p, h_prime, b, C, c, epk, sigma) = hash(policy_str, msk, mpk, pk, assump_size, ID_j)

    if (verify(mpk, m, p, h_prime, b, C, c, epk, sigma) == 0):
        print("Successful verification.")
    else:
        print("Verification failed.")

    (m_prime, p_prime, h_prime, b, C_prime, c_prime, epk_prime, sigma_prime) = adapt(mpk, msk, sk_delta, m, h_prime, b, C, policy_str, assump_size, ID_j, pk, sk)

    if (verify(mpk, m_prime, p_prime, h_prime, b, C_prime, c_prime, epk_prime, sigma_prime) == 0):
        print("Successful verification.")
    else:
        print("Verification failed.")

    if (judge(msk, mpk, m, p, h_prime, b, C, c, epk, sigma, m_prime, p_prime, C_prime, c_prime, epk_prime,
                    sigma_prime, ID_i) == 0):
        print("Successful verification.")
    else:
        print("Verification failed.")