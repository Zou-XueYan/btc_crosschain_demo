OntCversion = '2.0.0'
"""
An Example of OEP-4
"""
from ontology.libont import byte2int, hexstring2bytes, hexstring2address, bytes2hexstring
from ontology.interop.Ontology.Native import Invoke
from ontology.interop.Ontology.Contract import Migrate
from ontology.interop.System.Action import RegisterAction
from ontology.interop.Ontology.Runtime import Base58ToAddress
from ontology.interop.System.Storage import Put, GetContext, Get, Delete
from ontology.interop.System.ExecutionEngine import GetExecutingScriptHash
from ontology.interop.System.Runtime import CheckWitness, Notify, Serialize, Deserialize
from ontology.builtins import concat, state
from ontology.libont import bytearray_reverse


ZERO_ADDRESS = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
CROSS_CHAIN_CONTRACT_ADDRESS = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09')

ctx = GetContext()
CONTRACT_ADDRESS = GetExecutingScriptHash()

NAME = 'BTCX'
SYMBOL = 'BTCX'
DECIMALS = 8
FACTOR = 100000000
TOTAL_AMOUNT = 100000000
BALANCE_PREFIX = bytearray(b'\x01')
APPROVE_PREFIX = b'\x02'
SUPPLY_KEY = 'TotalSupply'

TransferEvent = RegisterAction("transfer", "from", "to", "amount")
ApprovalEvent = RegisterAction("approval", "owner", "spender", "amount")
LockEvent = RegisterAction("lock", "to_chainId", "fee", "from_address", "to_address", "amount")
UnlockEvent = RegisterAction("unlock", "OEP-4 Address", "amount")

def Main(operation, args):
    """
    :param operation:
    :param args:
    :return:
    """
    if operation == 'init':
        return init()

    if operation == 'name':
        return name()

    if operation == 'symbol':
        return symbol()

    if operation == 'decimals':
        return decimals()

    if operation == 'totalSupply':
        return totalSupply()

    if operation == 'balanceOf':
        acct = args[0]
        return balanceOf(acct)

    if operation == 'transfer':
        from_acct = args[0]
        to_acct = args[1]
        amount = args[2]
        return transfer(from_acct, to_acct, amount)

    if operation == 'transferMulti':
        return transferMulti(args)

    if operation == 'transferFrom':
        spender = args[0]
        from_acct = args[1]
        to_acct = args[2]
        amount = args[3]
        return transferFrom(spender, from_acct, to_acct, amount)

    if operation == 'approve':
        owner = args[0]
        spender = args[1]
        amount = args[2]
        return approve(owner, spender, amount)

    if operation == 'allowance':
        owner = args[0]
        spender = args[1]
        return allowance(owner, spender)

    if operation == 'lock':
        to_chainId = args[0]
        to_contract = args[1]
        fee = args[2]
        from_address = args[3]
        to_address = args[4]
        amount = args[5]
        return lock(to_chainId, to_contract, fee, from_address, to_address, amount)

    if operation == 'unlock':
        return unlock(args[0])

    raise Exception("method not supported")


def init():
    """
    initialize the contract, put some important info into the storage in the blockchain
    :return:
    """
    if Get(ctx, SUPPLY_KEY):
        Notify("Already initialized!")
        return False
    else:
        total = TOTAL_AMOUNT * FACTOR

        Put(ctx, concat(BALANCE_PREFIX, CONTRACT_ADDRESS), total)
        Put(ctx, SUPPLY_KEY, total)

        TransferEvent("", CONTRACT_ADDRESS, total)

        return True

def name():
    """
    :return: name of the token
    """
    return NAME


def symbol():
    """
    :return: symbol of the token
    """
    return SYMBOL


def decimals():
    """
    :return: the decimals of the token
    """
    return DECIMALS


def totalSupply():
    """
    :return: the total supply of the token
    """
    return Get(ctx, SUPPLY_KEY)


def balanceOf(account):
    """
    :param account:
    :return: the token balance of account
    """
    if len(account) != 20:
        raise Exception("address length error")
    return Get(ctx, concat(BALANCE_PREFIX, account))


def transfer(from_acct, to_acct, amount):
    """
    Transfer amount of tokens from from_acct to to_acct
    :param from_acct: the account from which the amount of tokens will be transferred
    :param to_acct: the account to which the amount of tokens will be transferred
    :param amount: the amount of the tokens to be transferred, >= 0
    :return: True means success, False or raising exception means failure.
    """
    if len(to_acct) != 20 or len(from_acct) != 20:
        raise Exception("address length error")
    if CheckWitness(from_acct) == False or amount < 0:
        return False
    assert (_transfer(from_acct, to_acct, amount))
    return True


def _transfer(_from, _to, _amount):
    fromKey = concat(BALANCE_PREFIX, _from)
    fromBalance = Get(ctx, fromKey)
    if _amount > fromBalance:
        return False
    if _amount == fromBalance:
        Delete(ctx, fromKey)
    else:
        Put(ctx, fromKey, fromBalance - _amount)
    toKey = concat(BALANCE_PREFIX, _to)
    toBalance = Get(ctx, toKey)
    Put(ctx, toKey, toBalance + _amount)

    TransferEvent(_from, _to, _amount)

    return True


def transferMulti(args):
    """
    :param args: the parameter is an array, containing element like [from, to, amount]
    :return: True means success, False or raising exception means failure.
    """
    for p in args:
        if len(p) != 3:
            raise Exception("transferMulti params error.")
        if transfer(p[0], p[1], p[2]) == False:
            raise Exception("transferMulti failed.")
    return True


def approve(owner, spender, amount):
    """
    owner allow spender to spend amount of token from owner account
    Note here, the amount should be less than the balance of owner right now.
    :param owner:
    :param spender:
    :param amount: amount>=0
    :return: True means success, False or raising exception means failure.
    """
    if len(spender) != 20 or len(owner) != 20:
        raise Exception("address length error")
    if CheckWitness(owner) == False:
        return False
    if amount > balanceOf(owner) or amount < 0:
        return False

    key = concat(concat(APPROVE_PREFIX, owner), spender)
    Put(ctx, key, amount)

    ApprovalEvent(owner, spender, amount)

    return True


def transferFrom(spender, from_acct, to_acct, amount):
    """
    spender spends amount of tokens on the behalf of from_acct, spender makes a transaction of amount of tokens
    from from_acct to to_acct
    :param spender:
    :param from_acct:
    :param to_acct:
    :param amount:
    :return:
    """
    if len(spender) != 20 or len(from_acct) != 20 or len(to_acct) != 20:
        raise Exception("address length error")
    if CheckWitness(spender) == False:
        return False

    fromKey = concat(BALANCE_PREFIX, from_acct)
    fromBalance = Get(ctx, fromKey)
    if amount > fromBalance or amount < 0:
        return False

    approveKey = concat(concat(APPROVE_PREFIX, from_acct), spender)
    approvedAmount = Get(ctx, approveKey)
    toKey = concat(BALANCE_PREFIX, to_acct)

    if amount > approvedAmount:
        return False
    elif amount == approvedAmount:
        Delete(ctx, approveKey)
        Put(ctx, fromKey, fromBalance - amount)
    else:
        Put(ctx, approveKey, approvedAmount - amount)
        Put(ctx, fromKey, fromBalance - amount)

    toBalance = Get(ctx, toKey)
    Put(ctx, toKey, toBalance + amount)

    TransferEvent(from_acct, to_acct, amount)

    return True


def allowance(owner, spender):
    """
    check how many token the spender is allowed to spend from owner account
    :param owner: token owner
    :param spender:  token spender
    :return: the allowed amount of tokens
    """
    key = concat(concat(APPROVE_PREFIX, owner), spender)
    return Get(ctx, key)

def _serialzieArgs(_map):
    buff = None
    buff = WriteVarBytes(_map["address"], buff)
    buff = WriteUint64(_map["amount"], buff)
    return buff

def _deserializeArgs(buff):
    res = readVarBytes(buff, 0)
    toAddress = res[0]
    off = res[1]
    res = readUint64(buff, off)
    amount = res[0]
    return [toAddress, amount]


def lock(to_chainId, to_contract, fee, from_address, to_address, amount):
    """

    :param to_chainId:
    :param fee:
    :param address:
    :param amount:
    :return:
    """

    assert (amount > 0 and fee >= 0)
    assert (CheckWitness(from_address))

    assert (transfer(from_address, CONTRACT_ADDRESS, amount))

    input_map = {
        "address": to_address,
        "amount": amount
    }

    input_bytes = _serialzieArgs(input_map)

    param = state(to_chainId, to_contract, fee, "unlock", input_bytes)
    assert (Invoke(0, CROSS_CHAIN_CONTRACT_ADDRESS, "createCrossChainTx", param))

    LockEvent(to_chainId, fee, from_address, to_address, amount)
    return True

def unlock(params):
    """

    :param params:
    :return:
    """
    mp = _deserializeArgs(params)
    address = mp[0]
    amount = mp[1]

    assert (amount > 0)
    assert (isAddress(address))
    assert (CheckWitness(CROSS_CHAIN_CONTRACT_ADDRESS))

    assert(_transfer(CONTRACT_ADDRESS, address, amount))

    UnlockEvent(address, amount)
    return True


def isAddress(address):
    """
    check the address is legal address.
    :param address:
    :return:True or raise exception.
    """
    assert (len(address) == 20 and address != ZERO_ADDRESS)
    return True


def Add(a, b):
    """
    Adds two numbers, throws on overflow.
    :param a:operand a
    :param b:operand b
    :return:
    """
    c = a + b
    assert (c >= a)
    return c


def Sub(a, b):
    """
    Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
    :param a: operand a
    :param b: operand b
    :return: a - b if a - b > 0 or revert the transaction.
    """
    assert (a >= b)
    return a - b

def readBool(buff, off):
    if buff[off:off+1] == 1:
        return [True, off+1]
    else:
        return [False, off+1]


def readByte(buff, off):
    return [buff[off:off+1], off+1]

def readBytes(buff, off, count):
    return [buff[off:off+count], off+count]


def readUint8(buff, off):
    return [buff[off:off+1], off+1]


def readUint16(buff, off):
    # return buff[:2]
    return [_convertBytes32ToNum(buff[off:off+2], 2), off+2]


def readUint32(buff, off):
    # return buff[:4]
    return [_convertBytes32ToNum(buff[off:off+4], 4), off+4]


def readUint64(buff, off):
    # return buff[:8]
    res = _convertBytes32ToNum(buff[off:], 8)
    return [res, off+8]


def readUint255(buff, off):
    return [_convertBytes32ToNum(buff[off:off+32], 32), off+32]


def readVarUint(buff, off):
    t = buff[off:off+1]
    off = off + 1
    if t == b'\xfd':
        return readUint16(buff, off)
    elif t == b'\xfe':
        return readUint32(buff, off)
    elif t == b'\xff':
        return readUint64(buff, off)
    else:
        return [t, off]


def readVarBytes(buff, off):
    res = readVarUint(buff, off)
    count = res[0]
    off = res[1]
    return readBytes(buff, off, count)


def readAddress(buff, off):
    return [buff[off:off+20], off+20]


def WriteBool(v, buff):
    assert (v == 0 or v == 1)
    buff = concat(buff, v)
    return buff


def WriteByte(v, buff):
    val = v[0:1]
    buff = concat(buff, val)
    return buff


def WriteUint8(v, buff):
    assert (v >= 0 and v <= 0XFF)
    buff = concat(buff, v[0:1])
    return buff


def WriteUint16(v, buff):
    assert (v >= 0 and v <= 0xFFFF)
    buff = concat(buff, v[0:2])
    buff = concat(buff, _convertNum2Bytes32(v, 2))
    return buff


def WriteUint32(v, buff):
    assert (v >= 0 and v <= 0xFFFFFFFF)
    buff = concat(buff, _convertNum2Bytes32(v, 4))
    return buff


def WriteUint64(v, buff):
    assert (v >= 0 and v <= 0xFFFFFFFFFFFFFFFF)
    # buff = concat(buff, v[0:8])
    buff = concat(buff, _convertNum2Bytes32(v, 8))
    return buff


def WriteUint255(v, buff):
    assert (v >= 0 and v <= 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    return WriteBytes(_convertNum2Bytes32(v, 32), buff)


def WriteVarUint(v, buff):

    if v < 0xFD:
        return WriteUint8(v, buff)
    elif v <= 0xFFFF:
        buff = concat(buff, 0xFD)
        return WriteUint16(v, buff)
    elif v <= 0xFFFFFFFF:
        buff = concat(buff, 0xFE)
        return WriteUint32(v, buff)
    else:
        buff = concat(buff, 0xFF)
        return WriteUint64(v, buff)


def WriteBytes(v, buff):
    return concat(buff, v)


def WriteVarBytes(v, buff):
    l = len(v)
    buff = WriteVarUint(l, buff)
    return WriteBytes(v, buff)


def _convertNum2Bytes32(_val, bytesLen):
    l = len(_val)
    Notify(["xxx", _val, l])
    if l < bytesLen:
        for i in range(bytesLen - l):
            _val = concat(_val, b'\x00')
    Notify(["yyy", _val, len(_val)])
    return _val


def _convertBytes32ToNum(_bs, bytesLen):
    assert (len(_bs) == bytesLen)
    firstNonZeroPostFromR2L = _getFirstNonZeroPosFromR2L(_bs, bytesLen)
    assert (firstNonZeroPostFromR2L >= 0)
    return _bs[:firstNonZeroPostFromR2L]


def _getFirstNonZeroPosFromR2L(_bs, bytesLen):
    for i in range(bytesLen):
        if _bs[bytesLen - i - 1:bytesLen - i] != b'\x00':
            return bytesLen - i
    return -1
