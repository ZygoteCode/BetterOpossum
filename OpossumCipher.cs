namespace BetterOpossum
{
    internal class OpossumCipher
    {
        private const int BlockSizeBits = 2048;
        private const int KeySizeBits = 2048;
        private const int IvSizeBits = 256;

        private const int BlockSizeBytes = BlockSizeBits / 8;
        private const int KeySizeBytes = KeySizeBits / 8;
        private const int IvSizeBytes = IvSizeBits / 8;

        private int NumberOfRounds = 160;

        private readonly byte[] SBox = new byte[256];
        private readonly byte[] InvSBox = new byte[256];

        private readonly int[] PermutationTable = new int[BlockSizeBytes];

        public OpossumCipher(int numberOfRounds = 160)
        {
            NumberOfRounds = numberOfRounds;
            InitializeSBoxAndPermutation();
        }

        private void InitializeSBoxAndPermutation()
        {
            for (int i = 0; i < 256; i++)
            {
                SBox[i] = (byte)i;
            }

            Random rng = new Random(42);

            for (int i = SBox.Length - 1; i > 0; i--)
            {
                int j = rng.Next(i + 1);
                byte temp = SBox[i];
                SBox[i] = SBox[j];
                SBox[j] = temp;
            }

            for (int i = 0; i < 256; i++)
            {
                InvSBox[SBox[i]] = (byte)i;
            }

            int matrixSize = 16;

            if (matrixSize * matrixSize != BlockSizeBytes)
            {
                for (int i = 0; i < BlockSizeBytes; i++)
                {
                    PermutationTable[i] = (i + BlockSizeBytes - 5) % BlockSizeBytes;
                }
            }
            else
            {
                for (int row = 0; row < matrixSize; row++)
                {
                    for (int col = 0; col < matrixSize; col++)
                    {
                        int originalIndex = row * matrixSize + col;
                        int newCol = (col + matrixSize - row) % matrixSize;
                        int newIndex = row * matrixSize + newCol;
                        PermutationTable[originalIndex] = newIndex;
                    }
                }
            }
        }

        private byte[][] KeyExpansion(byte[] masterKey)
        {
            if (masterKey == null || masterKey.Length != KeySizeBytes)
            {
                throw new ArgumentException($"The key must be of {KeySizeBytes} bytes.", nameof(masterKey));
            }

            byte[][] roundKeys = new byte[NumberOfRounds + 1][];
            byte[] expandedKey = new byte[(NumberOfRounds + 1) * BlockSizeBytes];

            Buffer.BlockCopy(masterKey, 0, expandedKey, 0, KeySizeBytes);

            byte[] temp = new byte[BlockSizeBytes];

            for (int i = KeySizeBytes; i < expandedKey.Length; i += BlockSizeBytes)
            {
                Buffer.BlockCopy(expandedKey, i - BlockSizeBytes, temp, 0, BlockSizeBytes);
                temp = RotateBytesLeft(temp, 3);

                for (int j = 0; j < temp.Length; j++)
                {
                    if (j % 4 == 0)
                    {
                        temp[j] = SBox[temp[j]];
                    }
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
            int groupSize = 16;
            byte[] tempGroup = new byte[groupSize];

            for (int groupStart = 0; groupStart < BlockSizeBytes; groupStart += groupSize)
            {
                Buffer.BlockCopy(state, groupStart, tempGroup, 0, groupSize);

                for (int i = 0; i < groupSize; i++)
                {
                    byte nextByte = tempGroup[(i + 1) % groupSize];
                    byte rotatedNextByte = (byte)((nextByte << 3) | (nextByte >> 5));
                    state[groupStart + i] ^= rotatedNextByte;
                    state[groupStart + i] ^= tempGroup[(i + groupSize - 1) % groupSize];
                }
            }
        }

        private void AddRoundKey(byte[] state, byte[] roundKey)
        {
            XORBytes(state, 0, roundKey, 0, state, 0, BlockSizeBytes);
        }

        private void ApplyRoundDependentTransforms(byte[] state, int roundNumber)
        {
            int rotationAmount = (roundNumber % 8) + 1;
            byte[] rotatedState = RotateBitsLeft(state, rotationAmount);
            Buffer.BlockCopy(rotatedState, 0, state, 0, BlockSizeBytes);
            byte xorPatternByte = (byte)(roundNumber * 17 + 83);

            for (int i = 0; i < state.Length; i++)
            {
                state[i] ^= (byte)(xorPatternByte + i);
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
            return ProcessCtr(plaintext, key, iv);
        }

        public byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv)
        {
            return ProcessCtr(ciphertext, key, iv);
        }

        private byte[] ProcessCtr(byte[] inputData, byte[] key, byte[] iv)
        {
            if (iv == null || iv.Length != IvSizeBytes)
            {
                throw new ArgumentException($"The IV must be of {IvSizeBytes} bytes.", nameof(iv));
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
            if (data == null || data.Length == 0)
            {
                return data;
            }

            shift %= data.Length;

            if (shift == 0)
            {
                return data;
            }

            if (shift < 0)
            {
                shift += data.Length;
            }

            byte[] rotated = new byte[data.Length];

            Buffer.BlockCopy(data, shift, rotated, 0, data.Length - shift);
            Buffer.BlockCopy(data, 0, rotated, data.Length - shift, shift);

            return rotated;
        }

        private byte[] RotateBitsLeft(byte[] data, int bitShift)
        {
            if (data == null || data.Length == 0)
            {
                return data;
            }

            int totalBits = data.Length * 8;
            bitShift %= totalBits;

            if (bitShift == 0)
            {
                return data;
            }

            if (bitShift < 0)
            {
                bitShift += totalBits;
            }

            byte[] rotated = new byte[data.Length];
            int byteShift = bitShift / 8;
            int remainingBitShift = bitShift % 8;

            for (int i = 0; i < data.Length; i++)
            {
                int sourceIndex = (i - byteShift + data.Length) % data.Length;
                int prevSourceIndex = (sourceIndex - 1 + data.Length) % data.Length;

                byte currentByte = data[sourceIndex];
                byte prevByte = data[prevSourceIndex];

                rotated[i] = (byte)((currentByte << remainingBitShift) | (prevByte >> (8 - remainingBitShift)));
            }

            return rotated;
        }
    }
}