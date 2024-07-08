import math
import os
import statistics
import time
from collections.abc import Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, CipherContext
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.padding import PaddingContext, PKCS7

original_plaintext_size: int = 128
test_times: int = max(10, min(int(math.sqrt(original_plaintext_size) / 1.5), 60))


class InvalidDataError(Exception):
    """
    填充错误或 HMAC 校验错误都会抛出此异常。
    """
    def __init__(self) -> None:
        super().__init__("非法数据。数据可能被篡改。")


def average_number_of(numbers: Sequence[int | float]) -> float:
    """
    计算平均数
    :param numbers: 存放数据的序列
    :return: 平均数
    """
    return sum(numbers) / len(numbers)


def bytes_str(data: bytes | bytearray) -> str:
    """
    将二进制数据按十六进制生成格式化字符串
    :param data: 二进制数据
    :return: 每个字节都按照十六进制打印，一行最长 16 个字节
    """
    result: list[str] = []
    for i in range(0, len(data), 16):
        result.append(' '.join([f'{byte:02X}' for byte in data[i:i + 16]]))
    return '\n'.join(result)


def bytes_xor(x: bytes | bytearray, y: bytes | bytearray) -> bytes:
    """
    将两段二进制数据做异或
    :param x: 一段二进制数据
    :param y: 一段二进制数据
    :return: 两段二进制数据做异或后的数据
    """
    return bytes(b1 ^ b2 for b1, b2 in zip(x, y))


def aes_128_cbc_hmac_sha256_encrypt(original_data: bytes, initialization_vector: bytes) -> bytes:
    """
    对任意长度的数据做 AES-128-CBC 加密，参考 TLS 的实现，先对原始数据做 HMAC-SHA256，然后填充，然后再整体加密。
    :param original_data: 任意长度的原始数据
    :param initialization_vector: 初始化向量
    :return: AES-128-CBC-HMAC-SHA256 加密后的数据
    """
    global aes_key, hmac_key  # 我们假设 alice 和 bob 已经协商好 aes 密钥和 hmac 密钥

    # 计算原始数据的 HMAC-SHA256
    hmac_calculator: HMAC = HMAC(hmac_key, SHA256(), backend=default_backend())
    hmac_calculator.update(original_data)
    extracted_hmac_digest = hmac_calculator.finalize()
    print('HMAC 摘要:', bytes_str(extracted_hmac_digest) + '\n', sep='\n')

    # 将 HMAC 附加到数据后
    data_with_hmac: bytes = original_data + extracted_hmac_digest
    print('带有 HMAC 的原始数据:', bytes_str(data_with_hmac) + '\n', sep='\n')

    # 填充数据
    padder: PaddingContext = PKCS7(algorithms.AES.block_size).padder()
    padded_data: bytes = padder.update(data_with_hmac) + padder.finalize()
    print('填充后带有 HMAC 的原始数据:', bytes_str(padded_data) + '\n', sep='\n')

    # 创建一个加密器实例
    cipher: Cipher = Cipher(algorithms.AES(aes_key), modes.CBC(initialization_vector), backend=default_backend())
    encryptor: CipherContext = cipher.encryptor()

    # 加密数据
    encrypted_data: bytes = encryptor.update(padded_data) + encryptor.finalize()
    print('加密后的数据:', bytes_str(encrypted_data) + '\n', sep='\n')

    return encrypted_data


def remove_pkcs7_padding(data: bytes | bytearray) -> bytes:
    """
    按照 PKCS7 的规则移除填充，如果末尾没有按照 PKCS7 的规则填充，那么会抛出 InvalidDataError 异常。
    :param data: 二进制数据
    :return: 去掉填充的二进制数据
    """
    unpadder: PaddingContext = PKCS7(algorithms.AES.block_size).unpadder()
    try:
        data_without_padding = unpadder.update(data) + unpadder.finalize()
    except ValueError:
        raise InvalidDataError()
    else:
        return data_without_padding


def aes_128_cbc_hmac_sha256_decrypt(encrypted_data: bytes, initialization_vector: bytes) -> bytes:
    """
    对一段数据尝试做 AES-128-CBC-HMAC-SHA256 的解密，填充失败或者 HMAC 校验失败都会抛出相同的异常
    :param encrypted_data: 完整的加密后的数据
    :param initialization_vector: 初始化向量
    :return: 去除了 HMAC 和填充的解密后的原始数据
    """
    global aes_key, hmac_key  # 我们假设 alice 和 bob 已经协商好 aes 密钥和 hmac 密钥

    # 创建一个解密器实例
    cipher: Cipher = Cipher(algorithms.AES(aes_key), modes.CBC(initialization_vector), backend=default_backend())
    decryptor: CipherContext = cipher.decryptor()

    # 解密数据
    decrypted_data: bytes = decryptor.update(encrypted_data) + decryptor.finalize()

    # 验证填充的合法性后去除填充
    data_without_padding: bytes = remove_pkcs7_padding(decrypted_data)

    # 提取 HMAC 和 data
    extracted_hmac_digest = data_without_padding[-32:]
    extracted_original_data = data_without_padding[:-32]

    # 校验 HMAC
    hmac_calculator: HMAC = HMAC(hmac_key, SHA256(), backend=default_backend())
    hmac_calculator.update(extracted_original_data)
    try:
        hmac_calculator.verify(extracted_hmac_digest)
    except InvalidSignature:
        raise InvalidDataError()
    else:
        return extracted_original_data


def get_decryption_time(encrypted_data: bytes, initialization_vector: bytes) -> int:
    """
    把一段数据和初始化向量发给服务器尝试解密，并记录解密所用的时间（纳秒）
    :param encrypted_data: 待解密的数据
    :param initialization_vector: 初始化向量
    :return: 解密所用的时间（纳秒）
    """
    start_time: int = time.perf_counter_ns()
    try:
        aes_128_cbc_hmac_sha256_decrypt(encrypted_data, initialization_vector)
    finally:
        return time.perf_counter_ns() - start_time


def simulate_padding_oracle_attack(
        encrypted_data: bytes,
        initialization_vector: bytes,
) -> bytes:
    """
    模拟填充 Oracle 攻击，输入加密数据、初始向量，测试次数和预热次数，返回解密后的明文
    :param encrypted_data: 加密后的数据
    :param initialization_vector: 初始化向量
    :return:
    """
    global test_times
    # 一个密文块的字节数是 16 字节（128 比特 / 8 比特每字节）
    block_bytes_size: int = algorithms.AES.block_size // 8

    # 把整个密文按照 AES 的块大小（16 字节）分组
    ciphertext_blocks: list[bytearray] = [
        bytearray(encrypted_data[block_start_index:block_start_index + block_bytes_size])
        for block_start_index in range(0, len(encrypted_data), block_bytes_size)
    ]

    # 用于存放猜测得到的明文块，每个明文块应该也是 128 比特（16 字节）大小的 bytes
    plaintext_blocks: list[bytes] = []

    # 遍历每个密文块
    for this_ciphertext_block_index in range(0, len(ciphertext_blocks)):
        # 获取前一个密文块，如果是第一个块则使用初始向量
        previous_ciphertext_block: bytearray = (
            ciphertext_blocks[this_ciphertext_block_index - 1]
            if this_ciphertext_block_index > 0 else
            initialization_vector
        )

        # 正在处理的密文块信息
        this_ciphertext_block: bytearray = ciphertext_blocks[this_ciphertext_block_index]

        # 初始化中间解密结果块
        intermediate_decrypted_block: bytearray = bytearray(block_bytes_size)

        # 从后向前逐字节处理
        for process_byte_index in range(block_bytes_size - 1, -1, -1):
            # 根据当前处理的字节索引生成填充字节
            padder: PaddingContext = PKCS7(algorithms.AES.block_size).padder()
            padding: bytes = padder.update(bytes(process_byte_index)) + padder.finalize()

            # 构造一个修改后的初始化向量，用于猜测当前字节的解密值
            modified_initialization_vector: bytearray = bytearray(bytes_xor(intermediate_decrypted_block, padding))
            print(f'为了破解密文块[{this_ciphertext_block_index}]的第 {process_byte_index} 字节，我们构造一个新的初始化向量：',
                  f'使用 {bytes_str(intermediate_decrypted_block)} (当前估计的解密的中间值)',
                  f'异或 {bytes_str(padding)} (填充)',
                  f'得到 {bytes_str(modified_initialization_vector)}',
                  f'然后尝试 256 种可能修改构造的新初始化向量的第 {process_byte_index} 字节',
                  f'将修改的新初始化向量和密文块[{this_ciphertext_block_index}]发给服务器尝试解密并记录时间',
                  f'为了避免异常值，我们重复测试 {test_times} 次',
                  sep='\n')

            # 初始化所有可能值的解密时间样本
            description_times_of_all_guesses: list[list[int]] = [[] for _ in range(256)]
            # 对每个可能的字节值进行多次解密测试并记录时间
            for _ in range(test_times):
                for byte_guess_value in range(256):
                    modified_initialization_vector[process_byte_index] = byte_guess_value
                    description_times_of_all_guesses[byte_guess_value].append(
                        get_decryption_time(bytes(this_ciphertext_block), modified_initialization_vector)
                    )

            # 计算所有可能值的解密时间的中位数
            median_decryption_times_of_all_guesses: list[int] = [
                statistics.median(description_times_of_some_guess)
                for description_times_of_some_guess in description_times_of_all_guesses
            ]

            # 找出解密时间中位数最大的字节值，作为最可能的解密字节值
            max_decryption_time: int = max(median_decryption_times_of_all_guesses)
            average_decryption_time: float = average_number_of(median_decryption_times_of_all_guesses)
            time_difference: float = max_decryption_time - average_decryption_time
            byte_guess_value: int = median_decryption_times_of_all_guesses.index(max_decryption_time)
            print(f'将我们构造的初始化向量的第 {process_byte_index} 字节修改为:',
                  f'0x{byte_guess_value:02X}', '的用时（中位数）最大，为', max_decryption_time, '纳秒')
            print(f'与平均用时（{average_decryption_time} 纳秒）相比多出：{time_difference} 纳秒')
            modified_initialization_vector[process_byte_index] = byte_guess_value
            intermediate_decrypted_block = bytearray(bytes_xor(modified_initialization_vector, padding))
            print(f'因此初始化向量改为：{bytes_str(modified_initialization_vector)}',
                  f'可以使用以下方法得到对中间解密的密文块[{this_ciphertext_block_index}]当前估计',
                  sep='\n')
            print(f'使用 {bytes_str(modified_initialization_vector)} (修改的初始化向量)',
                  f'异或 {bytes_str(padding)} (填充)',
                  f'得到 {bytes_str(intermediate_decrypted_block)}\n',
                  sep='\n')

        def previous_ciphertext_block_name() -> str:
            """
            对于密文块 i，如果处理 i == 0，那么前一个密文块是 IV，否则是 i - 1
            :return: 前一个密文块的名字
            """
            return f'密文块[{this_ciphertext_block_index - 1}]' if this_ciphertext_block_index > 0 else '初始化向量'

        # 计算出当前密文块的明文数据块
        plain_data_block: bytes = bytes_xor(previous_ciphertext_block, intermediate_decrypted_block)
        print(f'密文块[{this_ciphertext_block_index}]的中间解密值已经被完整估计，可以通过如下获得明文块[{this_ciphertext_block_index}]:',
              f'使用 {bytes_str(previous_ciphertext_block)}（{previous_ciphertext_block_name()})',
              f'异或 {bytes_str(intermediate_decrypted_block)} (密文块[{this_ciphertext_block_index}]的中间解密值)',
              f'得到 {bytes_str(plain_data_block)}\n',
              sep='\n')
        # 将解密得到的明文数据块添加到明文块列表中
        plaintext_blocks.append(plain_data_block)
    # 将所有明文块拼接成完整的明文数据并返回
    return b''.join(plaintext_blocks)


if __name__ == '__main__':
    aes_key: bytes = os.urandom(128 // 8)  # 生成 128 位 AES 密钥
    print('AES 加解密密钥:', bytes_str(aes_key) + '\n', sep='\n')

    hmac_key: bytes = os.urandom(256 // 8)  # 生成 256 位 HMAC-SHA256 密钥
    print('HMAC 密钥:', bytes_str(hmac_key) + '\n', sep='\n')

    initialization_value: bytes = os.urandom(algorithms.AES.block_size // 8)  # 生成 AES-CBC 初始化向量
    print('AES-CBC 初始化向量:', bytes_str(initialization_value) + '\n', sep='\n')

    original_plaintext: bytes = os.urandom(original_plaintext_size)  # 生成 original_plaintext_size 字节长度的原始明文
    print('原始明文:', bytes_str(original_plaintext) + '\n', sep='\n')

    # 生成 AES-128-CBC-HMAC-SHA256 加密密文
    encrypted_data: bytes = aes_128_cbc_hmac_sha256_encrypt(original_plaintext, initialization_value)

    print('模拟填充提示攻击:')
    guessed_data_with_hash_and_padding: bytes = simulate_padding_oracle_attack(encrypted_data, initialization_value)

    print('猜测的带有填充和 HMAC 的明文:', bytes_str(guessed_data_with_hash_and_padding) + '\n', sep='\n')
    try:
        guessed_data_with_hash: bytes = remove_pkcs7_padding(guessed_data_with_hash_and_padding)
    except InvalidDataError:
        print('最后一组猜测值填充错误。')
    else:
        guessed_data: bytes = guessed_data_with_hash[:-32]

        print(f'猜测的明文（移除了填充和 HMAC）:\n{bytes_str(guessed_data)}')
        if guessed_data == original_plaintext:
            print('猜测的明文等于原始明文。')
        else:
            print(f'猜测的明文不等于等于原始明文',
                  f'可以考虑增大 test_times: {test_times} 的值',
                  sep='，', end='。')
