import hashlib

class SessionKey:
    @staticmethod
    def get_android_id():
        """
        On Android 8.0 (API level 26) and higher versions of the platform, a 64-bit number (expressed as a hexadecimal string), unique to each combination of app-signing key, user, and device.
        """
        return '128DD4C5A3B1D5'

    @staticmethod
    def derive_session_key():
        combined = f'ketoprakkuahkacang|{SessionKey.get_android_id()[:4]}'
        digest = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        return digest[:32]
