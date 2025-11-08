using System.Security.Cryptography;

namespace BetterOpossum
{
    internal static class BetterOpossumSecure
    {
        public enum AeadAlgorithm : byte
        {
            ChaCha20Poly1305 = 0x01,
            AesGcm = 0x02
        }

        private const byte HeaderVersion = 0x01;
        private const int DefaultSaltLength = 32;
        private const int DefaultNonceLength = 12;
        private const int TagLength = 16;
        private const int DerivedKeyLength = 32;

        public static byte[] Encrypt(byte[] plaintext, byte[] masterKey, byte[]? associatedData = null, AeadAlgorithm alg = AeadAlgorithm.ChaCha20Poly1305)
        {
            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
            if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));
            if (masterKey.Length < 16) throw new ArgumentException("masterKey must be at least 16 bytes", nameof(masterKey));

            byte[] salt = new byte[DefaultSaltLength];
            byte[] nonce = new byte[DefaultNonceLength];
            RandomNumberGenerator.Fill(salt);
            RandomNumberGenerator.Fill(nonce);

            byte[] aeadKey = Hkdf.DeriveKey(masterKey, salt, info: GetInfoBytes(alg), outputLength: DerivedKeyLength);

            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[TagLength];

            if (alg == AeadAlgorithm.ChaCha20Poly1305)
            {
                using var chacha = new ChaCha20Poly1305(aeadKey);
                chacha.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            }
            else
            {
                using var aesgcm = new AesGcm(aeadKey);
                aesgcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            }

            int headerLen = 1 + 1 + 1 + DefaultSaltLength + 1 + DefaultNonceLength;
            int totalLen = headerLen + ciphertext.Length + tag.Length;
            byte[] package = new byte[totalLen];

            int pos = 0;
            package[pos++] = HeaderVersion;
            package[pos++] = (byte)alg;
            package[pos++] = (byte)DefaultSaltLength;
            Buffer.BlockCopy(salt, 0, package, pos, DefaultSaltLength); pos += DefaultSaltLength;
            package[pos++] = (byte)DefaultNonceLength;
            Buffer.BlockCopy(nonce, 0, package, pos, DefaultNonceLength); pos += DefaultNonceLength;
            Buffer.BlockCopy(ciphertext, 0, package, pos, ciphertext.Length); pos += ciphertext.Length;
            Buffer.BlockCopy(tag, 0, package, pos, tag.Length); pos += tag.Length;

            CryptographicOperations.ZeroMemory(aeadKey);

            return package;
        }

        public static byte[] Decrypt(byte[] package, byte[] masterKey, byte[]? associatedData = null)
        {
            if (package == null) throw new ArgumentNullException(nameof(package));
            if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));
            if (package.Length < 6 + TagLength) throw new CryptographicException("Package too small or corrupted");

            int pos = 0;
            byte version = package[pos++];
            if (version != HeaderVersion) throw new CryptographicException($"Unsupported version: {version}");

            AeadAlgorithm alg = (AeadAlgorithm)package[pos++];

            int saltLen = package[pos++];
            if (saltLen <= 0 || saltLen > 64) throw new CryptographicException("Invalid salt length");

            if (pos + saltLen > package.Length) throw new CryptographicException("Package truncated (salt)");
            byte[] salt = new byte[saltLen];
            Buffer.BlockCopy(package, pos, salt, 0, saltLen); pos += saltLen;

            int nonceLen = package[pos++];
            if (nonceLen <= 0 || nonceLen > 64) throw new CryptographicException("Invalid nonce length");
            if (pos + nonceLen > package.Length) throw new CryptographicException("Package truncated (nonce)");
            byte[] nonce = new byte[nonceLen];
            Buffer.BlockCopy(package, pos, nonce, 0, nonceLen); pos += nonceLen;

            int cipherPlusTagLen = package.Length - pos;
            if (cipherPlusTagLen < TagLength) throw new CryptographicException("No room for tag");

            int ciphertextLen = cipherPlusTagLen - TagLength;
            byte[] ciphertext = new byte[ciphertextLen];
            byte[] tag = new byte[TagLength];
            Buffer.BlockCopy(package, pos, ciphertext, 0, ciphertextLen); pos += ciphertextLen;
            Buffer.BlockCopy(package, pos, tag, 0, TagLength); pos += TagLength;

            byte[] aeadKey = Hkdf.DeriveKey(masterKey, salt, info: GetInfoBytes(alg), outputLength: DerivedKeyLength);

            byte[] plaintext = new byte[ciphertextLen];
            try
            {
                if (alg == AeadAlgorithm.ChaCha20Poly1305)
                {
                    using var chacha = new ChaCha20Poly1305(aeadKey);
                    chacha.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
                }
                else
                {
                    using var aesgcm = new AesGcm(aeadKey);
                    aesgcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
                }
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("Decryption failed (authentication failed or corrupted data)");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(aeadKey);
            }

            return plaintext;
        }

        private static byte[] GetInfoBytes(AeadAlgorithm alg)
        {
            return alg == AeadAlgorithm.ChaCha20Poly1305 ? System.Text.Encoding.UTF8.GetBytes("BetterOpossum:ChaCha20-Poly1305") : System.Text.Encoding.UTF8.GetBytes("BetterOpossum:AES-GCM");
        }

        private static class Hkdf
        {
            private const int HashLen = 32;

            public static byte[] DeriveKey(byte[] ikm, byte[] salt, byte[] info, int outputLength)
            {
                if (ikm == null) throw new ArgumentNullException(nameof(ikm));
                if (salt == null) throw new ArgumentNullException(nameof(salt));
                if (info == null) info = Array.Empty<byte>();
                if (outputLength <= 0) throw new ArgumentOutOfRangeException(nameof(outputLength));

                byte[] prk = Extract(salt, ikm);
                try
                {
                    return Expand(prk, info, outputLength);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(prk);
                }
            }

            private static byte[] Extract(byte[] salt, byte[] ikm)
            {
                byte[] realSalt = salt.Length == 0 ? new byte[HashLen] : salt;
                using var hmac = new HMACSHA256(realSalt);
                return hmac.ComputeHash(ikm);
            }

            private static byte[] Expand(byte[] prk, byte[] info, int length)
            {
                int n = (length + HashLen - 1) / HashLen;
                if (n > 255) throw new ArgumentOutOfRangeException(nameof(length), "Cannot expand to more than 255 * HashLen bytes using HKDF");

                byte[] okm = new byte[length];
                byte[] previous = Array.Empty<byte>();
                using var hmac = new HMACSHA256(prk);
                int copied = 0;
                for (byte i = 1; i <= n; i++)
                {
                    hmac.Initialize();
                    hmac.TransformBlock(previous, 0, previous.Length, null, 0);
                    hmac.TransformBlock(info, 0, info.Length, null, 0);
                    hmac.TransformFinalBlock(new byte[] { i }, 0, 1);
                    byte[] t = hmac.Hash!;

                    int toCopy = Math.Min(HashLen, length - copied);
                    Buffer.BlockCopy(t, 0, okm, copied, toCopy);
                    copied += toCopy;

                    previous = t;
                }

                CryptographicOperations.ZeroMemory(previous);
                return okm;
            }
        }
    }
}