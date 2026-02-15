class GBKomiError(Exception):
    pass


class DecryptionError(GBKomiError):
    pass


class EncryptionError(GBKomiError):
    pass