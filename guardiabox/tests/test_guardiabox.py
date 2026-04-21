"""
Tests unitaires pour GuardiaBox.

Couvre :
- security.crypto  : chiffrement / déchiffrement AES-GCM.
- security.password: validation de la robustesse des mots de passe.
- fileio.file_handler: validation des chemins de fichiers.
"""

import pytest
from cryptography.exceptions import InvalidTag

from security.crypto import (
    NONCE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
    decrypt_data,
    derive_key,
    encrypt_data,
)
from security.password import calculate_entropy, check_password_strength
from fileio.file_handler import validate_path


# ===========================================================================
# Tests — security.crypto
# ===========================================================================

class TestEncryptDecrypt:
    """Tests du cycle chiffrement / déchiffrement."""

    STRONG_PWD = "StrongP@ssw0rd!"

    def test_roundtrip_bytes(self):
        """Chiffrer puis déchiffrer doit restituer les données originales."""
        original = b"Hello, GuardiaBox!"
        encrypted = encrypt_data(original, self.STRONG_PWD)
        decrypted = decrypt_data(encrypted, self.STRONG_PWD)
        assert decrypted == original

    def test_roundtrip_empty_data(self):
        """Un payload vide doit survivre au cycle de chiffrement."""
        original = b""
        encrypted = encrypt_data(original, self.STRONG_PWD)
        decrypted = decrypt_data(encrypted, self.STRONG_PWD)
        assert decrypted == original

    def test_roundtrip_unicode_message(self):
        """Un texte UTF-8 avec accents doit être correctement chiffré/déchiffré."""
        original = "Bonjour le monde ! éàüçñ".encode("utf-8")
        encrypted = encrypt_data(original, self.STRONG_PWD)
        decrypted = decrypt_data(encrypted, self.STRONG_PWD)
        assert decrypted == original

    def test_roundtrip_large_data(self):
        """Un fichier de grande taille doit être correctement traité."""
        original = b"A" * 1_000_000  # 1 Mo
        encrypted = encrypt_data(original, self.STRONG_PWD)
        decrypted = decrypt_data(encrypted, self.STRONG_PWD)
        assert decrypted == original

    def test_wrong_password_raises_invalid_tag(self):
        """Un mauvais mot de passe doit lever InvalidTag."""
        data = b"Secret data"
        encrypted = encrypt_data(data, "CorrectP@ssw0rd!")
        with pytest.raises(InvalidTag):
            decrypt_data(encrypted, "WrongP@ssw0rd!!!")

    def test_encrypted_differs_from_plaintext(self):
        """Le chiffré ne doit pas être identique au texte en clair."""
        data = b"Plaintext data 123"
        encrypted = encrypt_data(data, self.STRONG_PWD)
        assert encrypted != data

    def test_two_encryptions_differ(self):
        """Deux chiffrements du même texte doivent produire des résultats différents."""
        data = b"Same data"
        enc1 = encrypt_data(data, self.STRONG_PWD)
        enc2 = encrypt_data(data, self.STRONG_PWD)
        assert enc1 != enc2

    def test_encrypted_output_contains_salt_nonce(self):
        """Le fichier chiffré doit au minimum contenir salt + nonce + tag."""
        data = b"Some data"
        encrypted = encrypt_data(data, self.STRONG_PWD)
        assert len(encrypted) >= SALT_SIZE + NONCE_SIZE + TAG_SIZE

    def test_corrupted_ciphertext_raises(self):
        """Des données altérées doivent lever une exception."""
        data = b"Important data"
        encrypted = encrypt_data(data, self.STRONG_PWD)
        # Modification des derniers octets (tag)
        corrupted = bytearray(encrypted)
        corrupted[-1] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt_data(bytes(corrupted), self.STRONG_PWD)

    def test_truncated_data_raises_value_error(self):
        """Des données trop courtes doivent lever ValueError."""
        with pytest.raises(ValueError):
            decrypt_data(b"\x00" * 10, self.STRONG_PWD)

    def test_derive_key_deterministic(self):
        """La même combinaison mot de passe + sel doit produire la même clé."""
        password = "DetTest@1234!"
        salt = b"\xde\xad\xbe\xef" * 4  # 16 octets
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        assert key1 == key2

    def test_derive_key_different_salts(self):
        """Des sels différents doivent produire des clés différentes."""
        password = "SamePass@1234!"
        key1 = derive_key(password, b"\x00" * 16)
        key2 = derive_key(password, b"\xFF" * 16)
        assert key1 != key2


# ===========================================================================
# Tests — security.password
# ===========================================================================

class TestPasswordStrength:
    """Tests du vérificateur de robustesse des mots de passe."""

    def test_strong_password_passes(self):
        """Un mot de passe robuste doit passer tous les critères."""
        is_strong, issues = check_password_strength("StrongP@ssw0rd!")
        assert is_strong is True
        assert issues == []

    def test_too_short_fails(self):
        """Un mot de passe trop court doit être refusé."""
        is_strong, issues = check_password_strength("Sh0rt!")
        assert is_strong is False
        assert any("caractères" in issue for issue in issues)

    def test_no_uppercase_fails(self):
        """L'absence de majuscule doit être signalée."""
        is_strong, issues = check_password_strength("nouppercase1@abcdef")
        assert is_strong is False
        assert any("majuscule" in issue for issue in issues)

    def test_no_lowercase_fails(self):
        """L'absence de minuscule doit être signalée."""
        is_strong, issues = check_password_strength("NOLOWERCASE1@ABCDEF")
        assert is_strong is False
        assert any("minuscule" in issue for issue in issues)

    def test_no_digit_fails(self):
        """L'absence de chiffre doit être signalée."""
        is_strong, issues = check_password_strength("NoDigitP@ssword!")
        assert is_strong is False
        assert any("chiffre" in issue for issue in issues)

    def test_no_special_char_fails(self):
        """L'absence de caractère spécial doit être signalée."""
        is_strong, issues = check_password_strength("NoSpecialChar1234")
        assert is_strong is False
        assert any("spécial" in issue for issue in issues)

    def test_empty_password_fails(self):
        """Un mot de passe vide doit échouer sur tous les critères."""
        is_strong, issues = check_password_strength("")
        assert is_strong is False
        assert len(issues) > 0

    def test_entropy_positive_for_complex_password(self):
        """L'entropie d'un mot de passe complexe doit être positive."""
        entropy = calculate_entropy("Complex@1234!")
        assert entropy > 0

    def test_entropy_zero_for_empty(self):
        """L'entropie d'une chaîne vide doit être nulle."""
        assert calculate_entropy("") == 0.0

    def test_entropy_increases_with_length(self):
        """Un mot de passe plus long doit avoir une entropie plus haute."""
        short = calculate_entropy("Ab1!")
        long_ = calculate_entropy("Ab1!Ab1!Ab1!Ab1!")
        assert long_ > short


# ===========================================================================
# Tests — fileio.file_handler
# ===========================================================================

class TestFileHandler:
    """Tests de la validation des chemins de fichiers."""

    def test_valid_relative_path(self):
        """Un chemin relatif normal doit être accepté."""
        path = validate_path("some/valid/path.txt")
        assert path is not None

    def test_valid_absolute_path(self):
        """Un chemin absolu sans traversal doit être accepté."""
        path = validate_path("C:/Users/user/documents/file.txt")
        assert path is not None

    def test_path_traversal_double_dot_rejected(self):
        """Un chemin contenant ``..`` doit lever ValueError."""
        with pytest.raises(ValueError, match="traversal"):
            validate_path("../../etc/passwd")

    def test_path_traversal_windows_style_rejected(self):
        """Un chemin Windows avec traversal doit lever ValueError."""
        with pytest.raises(ValueError, match="traversal"):
            validate_path("..\\..\\Windows\\System32")

    def test_null_byte_rejected(self):
        """Un chemin contenant un octet nul doit lever ValueError."""
        with pytest.raises(ValueError):
            validate_path("file\x00.txt")

    def test_simple_filename_accepted(self):
        """Un simple nom de fichier sans répertoire doit être accepté."""
        path = validate_path("document.txt")
        assert str(path) == "document.txt"
