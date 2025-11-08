namespace BetterOpossum
{
    public class BetterOpossumCipher
    {
        private OpossumCipher opossumCipher = new OpossumCipher();

        private const int BlockSizeBits = 4096;
        private const int KeySizeBits = 4096;
        private const int IvSizeBits = 512;

        private const int BlockSizeBytes = BlockSizeBits / 8;
        private const int KeySizeBytes = KeySizeBits / 8;
        private const int IvSizeBytes = IvSizeBits / 8;

        private int NumberOfRounds = 192;

        private readonly byte[] SBox = new byte[256];
        private readonly byte[] InvSBox = new byte[256];

        private readonly int[] PermutationTable = new int[BlockSizeBytes];

        private static readonly byte[] AesSBox = new byte[256] {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };

        private static readonly byte[] AesInvSBox = new byte[256] {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        };

        public BetterOpossumCipher(int numberOfRounds = 192)
        {
            NumberOfRounds = numberOfRounds;
            InitializeSBoxAndPermutation();
        }

        private void InitializeSBoxAndPermutation()
        {
            Buffer.BlockCopy(AesSBox, 0, SBox, 0, 256);
            Buffer.BlockCopy(AesInvSBox, 0, InvSBox, 0, 256);

            int matrixRows = 16;
            int matrixCols = BlockSizeBytes / matrixRows;

            if (matrixRows * matrixCols != BlockSizeBytes)
            {
                for (int i = 0; i < BlockSizeBytes; i++)
                {
                    PermutationTable[i] = (i + BlockSizeBytes - 5) % BlockSizeBytes;
                }
            }
            else
            {
                for (int row = 0; row < matrixRows; row++)
                {
                    for (int col = 0; col < matrixCols; col++)
                    {
                        int originalIndex = row * matrixCols + col;
                        int newCol = (col + matrixCols - (row % matrixCols)) % matrixCols;
                        int newIndex = row * matrixCols + newCol;
                        PermutationTable[originalIndex] = newIndex;
                    }
                }
            }
        }

        private byte[][] KeyExpansion(byte[] masterKey)
        {
            if (masterKey == null || masterKey.Length != KeySizeBytes)
            {
                throw new ArgumentException($"The key size must be of {KeySizeBytes} bytes.", nameof(masterKey));
            }

            byte[][] roundKeys = new byte[NumberOfRounds + 1][];
            byte[] expandedKey = new byte[(NumberOfRounds + 1) * BlockSizeBytes];

            Buffer.BlockCopy(masterKey, 0, expandedKey, 0, KeySizeBytes);

            byte[] temp = new byte[BlockSizeBytes];

            for (int i = KeySizeBytes; i < expandedKey.Length; i += BlockSizeBytes)
            {
                Buffer.BlockCopy(expandedKey, i - BlockSizeBytes, temp, 0, BlockSizeBytes);
                temp = RotateBytesLeft(temp, 13);

                for (int j = 0; j < temp.Length; j++)
                {
                    temp[j] = SBox[temp[j]];
                }

                byte roundConstant = (byte)(i / BlockSizeBytes);
                temp[0] ^= roundConstant;

                XORBytes(temp, 0, expandedKey, i - KeySizeBytes, temp, 0, BlockSizeBytes);
                Buffer.BlockCopy(temp, 0, expandedKey, i, BlockSizeBytes);
            }

            for (int r = 0; r < NumberOfRounds + 1; r++)
            {
                roundKeys[r] = new byte[BlockSizeBytes];
                Buffer.BlockCopy(expandedKey, r * BlockSizeBytes, roundKeys[r], 0, BlockSizeBytes);
            }

            return roundKeys;
        }

        private void SubBytes(byte[] state)
        {
            for (int i = 0; i < state.Length; i++)
            {
                state[i] = SBox[state[i]];
            }
        }

        private void PermuteBytes(byte[] state)
        {
            byte[] temp = new byte[BlockSizeBytes];
            for (int i = 0; i < BlockSizeBytes; i++)
            {
                temp[PermutationTable[i]] = state[i];
            }
            Buffer.BlockCopy(temp, 0, state, 0, BlockSizeBytes);
        }

        private void MixColumns(byte[] state)
        {
            int groupSize = 32;
            byte[] tempGroup = new byte[groupSize];

            for (int groupStart = 0; groupStart < BlockSizeBytes; groupStart += groupSize)
            {
                Buffer.BlockCopy(state, groupStart, tempGroup, 0, groupSize);

                for (int i = 0; i < groupSize; i++)
                {
                    byte a = tempGroup[i];
                    byte b = tempGroup[(i + 1) % groupSize];
                    byte c = tempGroup[(i + (groupSize / 2)) % groupSize];

                    byte rot_b = (byte)((b << 3) | (b >> 5));
                    byte rot_c = (byte)((c << 5) | (c >> 3));

                    state[groupStart + i] ^= (byte)(rot_b ^ rot_c ^ (byte)(i * 0x05 + 0x1F));
                }
            }
        }

        private void AddRoundKey(byte[] state, byte[] roundKey)
        {
            XORBytes(state, 0, roundKey, 0, state, 0, BlockSizeBytes);
        }

        private void ApplyRoundDependentTransforms(byte[] state, int roundNumber)
        {
            int rotationAmount = (roundNumber % 32) + 1;
            byte[] rotatedState = RotateBytesLeft(state, rotationAmount);
            Buffer.BlockCopy(rotatedState, 0, state, 0, BlockSizeBytes);

            for (int i = 0; i < state.Length; i++)
            {
                state[i] ^= SBox[(byte)(roundNumber + i)];
            }
        }

        private byte[] OpossumBlockEncrypt(byte[] inputBlock, byte[][] roundKeys)
        {
            if (inputBlock == null || inputBlock.Length != BlockSizeBytes)
            {
                throw new ArgumentException($"The input block must be of {BlockSizeBytes} bytes.", nameof(inputBlock));
            }

            byte[] state = new byte[BlockSizeBytes];
            Buffer.BlockCopy(inputBlock, 0, state, 0, BlockSizeBytes);
            AddRoundKey(state, roundKeys[0]);

            for (int round = 1; round < NumberOfRounds; round++)
            {
                SubBytes(state);
                PermuteBytes(state);
                MixColumns(state);
                ApplyRoundDependentTransforms(state, round);
                AddRoundKey(state, roundKeys[round]);
            }

            SubBytes(state);
            PermuteBytes(state);
            ApplyRoundDependentTransforms(state, NumberOfRounds);
            AddRoundKey(state, roundKeys[NumberOfRounds]);

            return state;
        }

        public byte[] Encrypt(byte[] plaintext, byte[] key, byte[] iv)
        {
            byte[] processed = ProcessCtr(plaintext, key, iv);
            byte[] encrypted = BetterOpossumSecure.Encrypt(processed, key.Take(32).ToArray(), iv, BetterOpossumSecure.AeadAlgorithm.ChaCha20Poly1305);
            byte[] encryptedAes = BetterOpossumSecure.Encrypt(encrypted, key.Take(32).ToArray(), iv, BetterOpossumSecure.AeadAlgorithm.AesGcm);
            byte[] encryptedOpossum = opossumCipher.Encrypt(encryptedAes, key.Take(256).ToArray(), iv.Take(32).ToArray());
            return encryptedOpossum;
        }

        public byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv)
        {
            byte[] decryptedOpossum = opossumCipher.Decrypt(ciphertext, key.Take(256).ToArray(), iv.Take(32).ToArray());
            byte[] decryptedAes = BetterOpossumSecure.Decrypt(decryptedOpossum, key.Take(32).ToArray(), iv);
            byte[] decrypted = BetterOpossumSecure.Decrypt(decryptedAes, key.Take(32).ToArray(), iv);
            byte[] processed = ProcessCtr(decrypted, key, iv);
            return processed;
        }

        private byte[] ProcessCtr(byte[] inputData, byte[] key, byte[] iv)
        {
            if (iv == null || iv.Length != IvSizeBytes)
            {
                throw new ArgumentException($"The IV size must be of {IvSizeBytes} bytes.", nameof(iv));
            }

            byte[][] roundKeys = KeyExpansion(key);
            byte[] outputData = new byte[inputData.Length];
            byte[] counterBlock = new byte[BlockSizeBytes];
            byte[] encryptedCounterBlock;

            Buffer.BlockCopy(iv, 0, counterBlock, 0, IvSizeBytes);

            int processedBytes = 0;
            while (processedBytes < inputData.Length)
            {
                encryptedCounterBlock = OpossumBlockEncrypt(counterBlock, roundKeys);

                int bytesToProcess = Math.Min(BlockSizeBytes, inputData.Length - processedBytes);
                XORBytes(inputData, processedBytes, encryptedCounterBlock, 0, outputData, processedBytes, bytesToProcess);

                processedBytes += bytesToProcess;
                IncrementCounter(counterBlock, IvSizeBytes);
            }

            return outputData;
        }

        private void XORBytes(byte[] a, int offsetA, byte[] b, int offsetB, byte[] result, int offsetResult, int length)
        {
            for (int i = 0; i < length; i++)
            {
                result[offsetResult + i] = (byte)(a[offsetA + i] ^ b[offsetB + i]);
            }
        }

        private void IncrementCounter(byte[] counterBlock, int counterStartIndex)
        {
            for (int i = BlockSizeBytes - 1; i >= counterStartIndex; i--)
            {
                if (counterBlock[i] == 0xFF)
                {
                    counterBlock[i] = 0x00;
                }
                else
                {
                    counterBlock[i]++;
                    return;
                }
            }
        }

        private byte[] RotateBytesLeft(byte[] data, int shift)
        {
            if (data == null || data.Length == 0) return data;
            shift %= data.Length;
            if (shift == 0) return data;
            if (shift < 0) shift += data.Length;

            byte[] rotated = new byte[data.Length];
            Buffer.BlockCopy(data, shift, rotated, 0, data.Length - shift);
            Buffer.BlockCopy(data, 0, rotated, data.Length - shift, shift);
            return rotated;
        }
    }
}