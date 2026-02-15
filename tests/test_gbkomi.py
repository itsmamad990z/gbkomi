import gbkomi


def test_encrypt_decrypt():
    password = "strongpassword123"
    message = b"secure message"

    encrypted = gbkomi.encrypt(message, password)
    decrypted = gbkomi.decrypt(encrypted, password)

    assert decrypted == message


def test_hash():
    data = "hello"
    assert len(gbkomi.sha256(data)) == 64
    assert len(gbkomi.sha512(data)) == 128
