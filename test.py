from bitarray import bitarray
import sys
import os
SCRIPT_DIR = os.path.dirname(os.path.abspath("/home/canyousee/CLionProjects/PAKE/KC-SPAKE2"))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import json
from binascii import hexlify, unhexlify
from hashlib import sha256
import params
import groups
from params import _Params
from ed25519_group import Ed25519Group
import pandas as pd
from bitarray.util import ba2base, base2ba, ba2int, int2ba
import six
from hashlib import sha256
from itertools import count
from pandas.core.frame import DataFrame
import code
import random
import time
import datetime
import hashlib
from random import randint
from math import floor, log,ceil
from scipy.spatial.distance import hamming




df = pd.read_csv(
    "/home/canyousee/CLionProjects/CIKM-exper/Data-profile-vector/Bin-city-employee.csv")
# build data tables
dataSet = []
dataSetBin = []
for i in range(0, df.shape[0]):
    dataSet.append(int(df.loc[i, 'int']))
    dataSetBin.append(df.loc[i, 'vector'])



def popcnt(x): return bin(x).count('1')
def dist(x, y): return popcnt(x ^ y)


def buildCovering(d, r):
    A = {}
    for v in range(1, 2**(r+1)):
        A[v] = 0
    for i in range(d):
        m = randint(1, 2**(r+1)-1)
       
        for v in range(1, 2**(r+1)):
            A[v] = A[v] + (1 << i) * (popcnt(m & v) % 2)
    return A


def buildDataStructure(A, S, r):
    D = {}
    for x in S:
        for v in range(1, 2**(r+1)):
            if not (x & A[v]) in D:
                D[x & A[v]] = set()
            D[x & A[v]].add(x)
    return D


def nearestNeighbor(A, D, r, y):
    infinity = float("inf")
    best, nn = infinity, None
    for v in range(1, 2**(r+1)):
        if (y & A[v]) in D:
            for x in D[y & A[v]]:
                if dist(x, y) < best:
                    best, nn = dist(x, y), x

        if best <= floor(log(v+1, 2)):
            return nn
    return None


def generateLSH(A, D, r, y):
    infinity = float("inf")
    best, nn = infinity, None
    for v in range(1, 2**(r+1)):
        if (y & A[v]) in D:
            return y & A[v]

def split_list(a_list, test):
    point= int(len(a_list)*test)
    return a_list[:point], a_list[point:]
"""
setup
"""


# LSH
test=0.2
test_set, train_set=split_list(dataSet,test)

n = ceil(len(dataSet)*(1-test)) # size of dataset
r = 5  # radius
d = 512  # dimen of vector
repetitions = 10000
begin_time = datetime.datetime.now()
print("Building data structure with", n, "vectors in",
      d, "dimensions and maximum radius", r, "...")
A =buildCovering(d, r)
D = buildDataStructure(A,train_set, r)

# SPAKE2
params = _Params(Ed25519Group)
entropy_f=os.urandom
g = params.group
a=g.arbitrary_element(b"A") # public parameter a

end_time=datetime.datetime.now() - begin_time
print("generate set up time:", end_time)

# generate LSH
begin_time = datetime.datetime.now()
y1= generateLSH(A, D, r, dataSet[13])
end_time=datetime.datetime.now() - begin_time
print("generate LSH time:", end_time)

idA=b"1"
idB=b"2"

# requireGen
begin_time = datetime.datetime.now()
pw = b"123456"
pw_scalar = params.group.password_to_scalar(pw)
xy_scalar = g.random_scalar(entropy_f) # random x
xy_elem = g.Base.scalarmult(xy_scalar) # g^x
message_elem = xy_elem.add(a.scalarmult(pw_scalar)) 
end_time=datetime.datetime.now() - begin_time
print("generate encrypted requirement time:", end_time)

#materialGen
begin_time = datetime.datetime.now()
pw = b"123456"
pw_scalar = params.group.password_to_scalar(pw)

xy1_scalar = g.random_scalar(entropy_f) # random y
xy1_elem = g.Base.scalarmult(xy1_scalar) # g^y = tag
pw_blinding = a.scalarmult(-pw_scalar) # a^-pw
w=message_elem.add(pw_blinding).scalarmult(xy1_scalar)
byte_xy1_elem=xy1_elem.to_bytes()
byte_w=w.to_bytes()
outbound_message = message_elem.to_bytes()
transcriptb = b"".join([sha256(pw).digest(),
                           sha256(idA).digest(), sha256(idB).digest(),
                           outbound_message, byte_xy1_elem, byte_w])
key = sha256(transcriptb).digest()
end_time=datetime.datetime.now() - begin_time
print("generate encrypted material time:", end_time)


begin_time = datetime.datetime.now()
wa=xy1_elem.scalarmult(xy_scalar)
byte_wa=wa.to_bytes()
transcripta = b"".join([sha256(pw).digest(),
                           sha256(idA).digest(), sha256(idB).digest(),
                           outbound_message, byte_xy1_elem, byte_wa])
keya = sha256(transcripta).digest()

print(key[:10]==keya[:10])
end_time=datetime.datetime.now() - begin_time
print("generate allowlist once:", end_time)



dquality_weather = pd.read_csv(
    "/home/canyousee/CLionProjects/CIKM-exper/Data-quality-address/WeatherSentiment_amt.csv")
# build data tables
data_worker=[]
for i in range(0, dquality_weather.shape[0]):
    data_worker.append(dquality_weather.loc[i, 'wId'])

for i in range(0,len(data_worker)):
    if(dquality_weather[dquality_weather['wId']==data_worker[i]].shape[0]<10):
        dquality_weather.drop(dquality_weather[dquality_weather['wId']==data_worker[i]].index)

data_worker=[]
dataSet_dquality_weather = []
for i in range(0, dquality_weather.shape[0]):
    dataSet_dquality_weather.append(dquality_weather.loc[i, :].values.tolist())
    data_worker.append(dataSet_dquality_weather[i][0])


def commit_gold(gold,pk):
    pw_hash = hashlib.pbkdf2_hmac('sha256',gold.encode(), pk, 100000)
    return pw_hash
def open_commit(gold, pk, gold_commit):
    pw_hash = hashlib.pbkdf2_hmac('sha256',gold.encode(), pk, 100000)
    return pw_hash==gold_commit

gold={}
qId_data=DataFrame(dquality_weather.qId.unique())
qId_data=qId_data.sample(n=60)

for i in range(0,qId_data.shape[0]):
    gold[qId_data.iloc[i,0]]=dquality_weather[dquality_weather['qId']==qId_data.iloc[i,0]]['ground'].iloc[0]

pk= os.urandom(16)

begin_time = datetime.datetime.now()
gold_commit=commit_gold(str(gold),pk)
end_time=datetime.datetime.now() - begin_time
print("generate gold commit:", end_time)

SEED_SIZE  = 48
GENERATOR  = 223
MODULUS    = 36389

FUNCTION_L = lambda x: x**2 - 2*x + 1


class MerkleHashTree():
    """  Merkle Hash Tree """
    
    def addLeaf(self, string):
        """ Create a new leaf node for the string 'd' """
        hashValue = hash(string)
        self.size += 1
        self._storeNode(self.size-1, self.size, hashValue)

    def mth(self, k1, k2):
        """ Merkle Tree Hash funcion recursively creates required nodes"""
       
        try:
            mNode = self._retrieveNode(k1, k2)
        except KeyError:   # no stored node, so make one
            k = k1 + largestPower2(k2-k1)
            mNode = hash(self.mth(k1, k) + self.mth(k,k2))
            self._storeNode(k1, k2, mNode)
        return mNode

    def auditPath(self, m, n=None):
        """ return a list of hash values for entry d(m) that proves
            that d(m) is contained in the nth root hash with 0 <= m < n
        """
        if not n: n = self.size
        def _auditPath(m, k1, k2):
            """ Recursively collect audit path """
            if (k2-k1) == 1:
                return [ ] # terminate with null list when range is a single node
            k = k1 + largestPower2(k2-k1)
            if m < k:
                path = _auditPath(m, k1, k) + [self.mth(k,k2),]
            else:
                path = _auditPath(m, k, k2) + [self.mth(k1,k),]
            return path
        
        return _auditPath(m, 0, n)

    def validPath(self, m, n, leaf_hash, root_hash, audit_path):
        """ Test if leaf_hash is contained under a root_hash
            as demonstrated by the audit_path """
        
        def _hashAuditPath(m, k1, k2, i):
            """ Recursively calculate hash value """
            if len(audit_path) == i:
                return leaf_hash
            k = k1 + largestPower2(k2-k1)
            ithAuditNode = audit_path[len(audit_path) - 1 - i]
            if m < k:
                hv = hash( _hashAuditPath(m, k1, k, i+1) + ithAuditNode )
            else:
                hv = hash(ithAuditNode + _hashAuditPath(m, k, k2, i+1) )
            return hv
           
        hv = _hashAuditPath(m, 0, n, 0)        
        return hv == root_hash
    
    def rootHash(self, n=None):
        """ Root hash of tree for nth root """
        if not n: n = self.size
        if n > 0:
            return self.mth(0, n)
        else:
            return hash('')  # empty tree is hash of null string
            
    def leafHash(self, m):
        """ Leaf hash value for mth entry """
        return self.mth(m, m+1)
            
    def hash(self, input):
        """ Wrapper for hash functions """
        return self._hashalg(input).digest()
     
    def __init__(self, HashAlg = sha256):
        self._hashalg = HashAlg
        self.size = 0 # number of leaf nodes in tree
        self._inittree()   # create empty mht
        
    def __len__(self):
        return self.size

    # Overload the following for persistant trees
    def _inittree(self):
        self.hashtree = {} 
        
    def _retrieveNode(self, k1, k2):
        return self.hashtree[(k1,k2)]
    
    def _storeNode(self, k1, k2, mNode):
        # leaf and non-leaf nodes in the same dictionary indexed by range tuple
        assert k1 < k2 <= self.size
        self.hashtree[(k1,k2)] = mNode
        
def largestPower2(n):
    """ Return the largest power of 2 less than n """
    lp2 = 1
    while lp2 < n :
        lp2 = lp2 << 1
    return lp2 >> 1

def function_H(first_half, second_half):
    mod_exp = bin(pow(GENERATOR, int(first_half, 2), MODULUS)).replace('0b', '').zfill(SEED_SIZE)
    hard_core_bit = 0
    for i in range(len(first_half)):
        hard_core_bit = (hard_core_bit ^ (int(first_half[i]) & int(second_half[i]))) % 2
    return mod_exp + second_half + str(hard_core_bit)


def function_G(initial_seed):
    binary_string = initial_seed
    result = ''
    for i in range(FUNCTION_L(SEED_SIZE)):
        first_half = binary_string[:len(binary_string)//2]
        second_half = binary_string[len(binary_string)//2:]
        binary_string = function_H(first_half, second_half)
        result += binary_string[-1]
        binary_string = binary_string[:-1]
    return result


def PRG(seed):
    if len(seed) > SEED_SIZE:
        print ("Inital seed too long: change the seed or set a new SEED_SIZE")
        
    output = function_G(seed)
    return output

dtemp=dquality_weather[dquality_weather['wId']==data_worker[0]]
quality={}
for i in range(0, dtemp.shape[0]):
   if dtemp.iloc[i,1] in gold.keys():
       if dtemp.iloc[i,2]!=dtemp.iloc[i,3]:

           quality[i]=dtemp.iloc[i,2]


c = bitarray(endian='little')
c.frombytes(keya[10:16])
seed=c.to01()

randoms=PRG(seed)
# random_values=[]
# for i in range(0,len(randoms)//8):
#     random_values.append(randoms[i*8:(i+1)*8])
begin_time = datetime.datetime.now()
MHT=MerkleHashTree()
for i in range(0,dquality_weather[dquality_weather['wId']==data_worker[0]].shape[0]):
    tId=1
    wId=data_worker[0]
    qId=dquality_weather[dquality_weather['wId']==data_worker[0]].iloc[i,1]
    answer=dquality_weather[dquality_weather['wId']==data_worker[0]].iloc[i,2]
    r=randoms[i*8:(i+1)*8]
    content=str(tId)+str(wId)+str(qId)+str(answer)+str(r)
    MHT.addLeaf(content)

root=MHT.rootHash()
MHT.auditPath(6)
MHT.auditPath(65)
MHT.auditPath(55)
end_time=datetime.datetime.now() - begin_time
print("generate prove:", end_time)


# verify

begin_time = datetime.datetime.now()
open_commit(str(gold),pk,gold_commit)

tId=1
wId=data_worker[0]
qId=dquality_weather[dquality_weather['wId']==data_worker[0]].iloc[i,1]
answer=dquality_weather[dquality_weather['wId']==data_worker[0]].iloc[i,2]
r=randoms[48:56]
content=str(tId)+str(wId)+str(qId)+str(answer)+str(r)

MHT.validPath(6,len(MHT),hash(content),root,MHT.auditPath(6))

MHT.validPath(6,len(MHT),hash(content),root,MHT.auditPath(6))

MHT.validPath(6,len(MHT),hash(content),root,MHT.auditPath(6))
end_time=datetime.datetime.now() - begin_time
print("generate verify:", end_time)