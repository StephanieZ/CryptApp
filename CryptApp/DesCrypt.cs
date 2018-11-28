using System.Collections.Generic;

namespace CryptApp
{

    public class DesCrypt
    {
        public const string Ascii64 =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        private long _desResult0;
        private long _desResult1;
        private int _saltbits;


        private readonly ushort[] _desInitialPermutation =
        {
          58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
        };

        private readonly ushort[] _desKeyGenerationPermutation =
        {
          57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
          10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
          63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
          14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
        };

        private readonly ushort[] _desKeyShifts =
        {
          1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
        };

        private readonly ushort[] _desKeyCompressionPermutation =
        {
          14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
          23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
          41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
          44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
        };

        private readonly ushort[,] _desSubstitutionBox =
        {
            {
              14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
              0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
              4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
              15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            },
            {
              15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
              3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
              0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
              13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            },
            {
              10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
              13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
              13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
              1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
            },
            {
              7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
              13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
              10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
              3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            },
            {
              2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
              14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
              4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
              11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
            },
            {
              12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
              10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
              9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
              4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
            },
            {
              4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
              13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
              1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
              6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
            },
            {
              13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
              1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
              7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
              2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
            }
        };

        readonly ushort[] _desPermutationBox =
        {
            16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
        };

        readonly long[] _desBits32 =
        {
            0x80000000, 0x40000000, 0x20000000, 0x10000000,
            0x08000000, 0x04000000, 0x02000000, 0x01000000,
            0x00800000, 0x00400000, 0x00200000, 0x00100000,
            0x00080000, 0x00040000, 0x00020000, 0x00010000,
            0x00008000, 0x00004000, 0x00002000, 0x00001000,
            0x00000800, 0x00000400, 0x00000200, 0x00000100,
            0x00000080, 0x00000040, 0x00000020, 0x00000010,
            0x00000008, 0x00000004, 0x00000002, 0x00000001
        };

        readonly int[] _bits28 =
        {
            0x08000000, 0x04000000, 0x02000000, 0x01000000,
            0x00800000, 0x00400000, 0x00200000, 0x00100000,
            0x00080000, 0x00040000, 0x00020000, 0x00010000,
            0x00008000, 0x00004000, 0x00002000, 0x00001000,
            0x00000800, 0x00000400, 0x00000200, 0x00000100,
            0x00000080, 0x00000040, 0x00000020, 0x00000010,
            0x00000008, 0x00000004, 0x00000002, 0x00000001
        };

        readonly long[] _bits24 =
        {
            0x00800000, 0x00400000, 0x00200000, 0x00100000,
            0x00080000, 0x00040000, 0x00020000, 0x00010000,
            0x00008000, 0x00004000, 0x00002000, 0x00001000,
            0x00000800, 0x00000400, 0x00000200, 0x00000100,
            0x00000080, 0x00000040, 0x00000020, 0x00000010,
            0x00000008, 0x00000004, 0x00000002, 0x00000001
        };

        readonly ushort[] _desBits8 = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};

        private readonly long[,] _invertedSubstitutionBox = new long[8, 64];
        private readonly long[,] _bitHandlingSubstitionBox = new long[4, 4096];
        private readonly long[] _initialPermutation = new long[64];
        private readonly long[] _finalPermutation = new long[64];
        private readonly long[] _invertedKeyPermutation = new long[64];
        readonly long[] _uKeyPermutation = new long[56];
        readonly long[] _invertedKeyCompressionPermutation = new long[56];
        readonly long[,] _initialPermutationMaskLeft = new long[8, 256];
        readonly long[,] _initialPermutationMaskRight = new long[8, 256];
        readonly long[,] _finalPermutationMaskLeft = new long[8, 256];
        readonly long[,] _finalPermutationMaskRight = new long[8, 256];
        readonly long[] _invertedPBoxPermutation = new long[32];
        readonly long[,] _pSubstitionBoxes = new long[4, 256];
        readonly long[,] _keyPermutationMaskLeft = new long[8, 128];
        readonly long[,] _keyPermutationMaskRight = new long[8, 128];
        readonly long[,] _compMaskLeft = new long[8, 128];
        readonly long[,] _compMaskRight = new long[8, 128];

        private readonly long[] _encryptionKeysLeft = new long[16];
        private readonly long[] _encryptionKeysRight = new long[16];


        public DesCrypt()
        {
          DesInitiatize();
        }

        private void DesInitiatize()
        {
            //Invert Substition Boxes
            // https://en.wikipedia.org/wiki/DES_supplementary_material#SubstitionBoxes
            for (var i = 0; i < 8; i++)
            {
                for (var j = 0; j < 64; j++)
                {
                  var b = (j & 0x20) | ((j & 1) << 4) | ((j >> 1) & 0xf);
                  _invertedSubstitutionBox[i, j] = _desSubstitutionBox[i, b];
                }
            }

            //Convert Substition Box into 4 arrays X 8 bits, each will handle 12 bits of input
            //
            for (var b = 0; b < 4; b++)
            {
                for (var i = 0; i < 64; i++)
                {
                    for (var j = 0; j < 64; j++)
                    {
                      _bitHandlingSubstitionBox[b, (i << 6) | j] =
                        (int) _invertedSubstitutionBox[(b << 1), i] << 4 |
                        (int) _invertedSubstitutionBox[(b << 1) + 1, j];
                    }
                }
            }

            //set up initial and final permutation and initialize inverted key permutation
            for (var i = 0; i < 64; i++)
            {
                _finalPermutation[i] = _desInitialPermutation[i] - 1;
                _initialPermutation[_finalPermutation[i]] = i;
                _invertedKeyPermutation[i] = 255;
            }

            //Invert the key permutation and initialize the inverted key compression permutation
            for (var i = 0; i < 56; i++)
            {
                _uKeyPermutation[i] = _desKeyGenerationPermutation[i] - 1;
                _invertedKeyPermutation[_uKeyPermutation[i]] = i;
                _invertedKeyCompressionPermutation[i] = 255;
            }

            //Invert the key compression permutation
            for (var i = 0; i < 48; i++)
            {
                _invertedKeyCompressionPermutation[_desKeyCompressionPermutation[i] - 1] = i;
            }

            //Set up mask arrays for initial and final permutations
            for (var k = 0; k < 8; k++)
            {
                //ushort i;
                int inbit;
                long obit;
                int i;
                for (i = 0; i < 256; i++)
                {
                    _initialPermutationMaskLeft[k, i] = 0;
                    _initialPermutationMaskRight[k, i] = 0;
                    _finalPermutationMaskLeft[k, i] = 0;
                    _finalPermutationMaskRight[k, i] = 0;
                    for (var j = 0; j < 8; j++)
                    {
                        inbit = 8 * k + j;
                      if ((i & _desBits8[j]) <= 0) continue;
                      obit = _initialPermutation[inbit];
                      if (obit < 32)
                        _initialPermutationMaskLeft[k, i] |= _desBits32[(int) obit];
                      else
                        _initialPermutationMaskRight[k, i] |= _desBits32[(int) obit - 32];

                      if ((obit = _finalPermutation[inbit]) < 32)
                        _finalPermutationMaskLeft[k, i] |= _desBits32[(int) obit];
                      else
                        _finalPermutationMaskRight[k, i] |= _desBits32[(int) obit - 32];
                    }
                }

                for (var x = 0; x < 128; x++)
                {
                    _keyPermutationMaskLeft[k, x] = 0;
                    _keyPermutationMaskRight[k, x] = 0;
                    for (var j = 0; j < 7; j++)
                    {
                      inbit = 8 * k + j;
                      if ((x & _desBits8[j + 1]) <= 0) continue;

                      if ((obit = _invertedKeyPermutation[inbit]) == 255)
                        continue;
                      if (obit < 28)
                        _keyPermutationMaskLeft[k, x] |= _bits28[obit];
                      else
                        _keyPermutationMaskRight[k, x] |= _bits28[obit - 28];
                    }

                    _compMaskLeft[k, x] = 0;
                    _compMaskRight[k, x] = 0;
                    for (var j = 0; j < 7; j++)
                    {
                      inbit = 7 * k + j;
                      if ((x & _desBits8[j + 1]) <= 0) continue;
                      if ((obit = _invertedKeyCompressionPermutation[inbit]) == 255) continue;
                      if (obit < 24)
                        _compMaskLeft[k, x] |= _bits24[(int) obit];
                      else
                        _compMaskRight[k, x] |= _bits24[(int) obit - 24];
                    }


                    // Invert the P-box permutation, and convert into OR-masks for
                    // handling the output of the S-box arrays setup above.            
                    for (var l = 0; l < 32; l++)
                      _invertedPBoxPermutation[_desPermutationBox[l] - 1] = l;

                    for (var b = 0; b < 4; b++)
                    {
                        for (var n = 0; n < 256; n++)
                        {
                            _pSubstitionBoxes[b, n] = 0;
                            for (var j = 0; j < 8; j++)
                            {
                              if ((n & _desBits8[j]) > 0)
                                _pSubstitionBoxes[b, n] |= _desBits32[_invertedPBoxPermutation[8 * b + j]];
                            }
                        }
                    }
                }
            }
        }



        public bool ComparePasswordHash(string password, string hash, string salt)
        {
            //reencrypt using the new algorith below and then compare the result (hope they match).
            var cryptedPassword = Descrypt(password, salt);

            return string.Equals(cryptedPassword, hash);
        }


        private void DesSetKey(IReadOnlyList<int> key)
        {
            long rawkey0 = (key[0] << 24) |
                           (key[1] << 16) |
                           (key[2] << 8) |
                           (key[3] << 0);

            long rawkey1 = (key[4] << 24) |
                           (key[5] << 16) |
                           (key[6] << 8) |
                           (key[7] << 0);

            /* Do key permutation and split into two 28-bit subkeys. */
            var k0 = _keyPermutationMaskLeft[0, ZeroFillRightShift(rawkey0, 25)]
                     | _keyPermutationMaskLeft[1, ZeroFillRightShift(rawkey0, 17) & 0x7f]
                     | _keyPermutationMaskLeft[2, ZeroFillRightShift(rawkey0, 9) & 0x7f]
                     | _keyPermutationMaskLeft[3, ZeroFillRightShift(rawkey0, 1) & 0x7f]
                     | _keyPermutationMaskLeft[4, ZeroFillRightShift(rawkey1, 25)]
                     | _keyPermutationMaskLeft[5, ZeroFillRightShift(rawkey1, 17) & 0x7f]
                     | _keyPermutationMaskLeft[6, ZeroFillRightShift(rawkey1, 9) & 0x7f]
                     | _keyPermutationMaskLeft[7, ZeroFillRightShift(rawkey1, 1) & 0x7f];
            var k1 = _keyPermutationMaskRight[0, ZeroFillRightShift(rawkey0, 25)]
                     | _keyPermutationMaskRight[1, ZeroFillRightShift(rawkey0, 17) & 0x7f]
                     | _keyPermutationMaskRight[2, ZeroFillRightShift(rawkey0, 9) & 0x7f]
                     | _keyPermutationMaskRight[3, ZeroFillRightShift(rawkey0, 1) & 0x7f]
                     | _keyPermutationMaskRight[4, ZeroFillRightShift(rawkey1, 25)]
                     | _keyPermutationMaskRight[5, ZeroFillRightShift(rawkey1, 17) & 0x7f]
                     | _keyPermutationMaskRight[6, ZeroFillRightShift(rawkey1, 9) & 0x7f]
                     | _keyPermutationMaskRight[7, ZeroFillRightShift(rawkey1, 1) & 0x7f];

            /* Rotate subkeys and do compression permutation. */
            var shifts = 0;
            for (var round = 0; round < 16; round++)
            {
              shifts += _desKeyShifts[round];

              var t0 = (k0 << shifts) | ZeroFillRightShift(k0, (28 - shifts));
              var t1 = (k1 << shifts) | ZeroFillRightShift(k1, (28 - shifts));

              _encryptionKeysLeft[round] = _compMaskLeft[0, ZeroFillRightShift(t0, 21) & 0x7f]
                                           | _compMaskLeft[1, ZeroFillRightShift(t0, 14) & 0x7f]
                                           | _compMaskLeft[2, ZeroFillRightShift(t0, 7) & 0x7f]
                                           | _compMaskLeft[3, t0 & 0x7f]
                                           | _compMaskLeft[4, ZeroFillRightShift(t1, 21) & 0x7f]
                                           | _compMaskLeft[5, ZeroFillRightShift(t1, 14) & 0x7f]
                                           | _compMaskLeft[6, ZeroFillRightShift(t1, 7) & 0x7f]
                                           | _compMaskLeft[7, t1 & 0x7f];

              _encryptionKeysRight[round] = _compMaskRight[0, ZeroFillRightShift(t0, 21) & 0x7f]
                                            | _compMaskRight[1, ZeroFillRightShift(t0, 14) & 0x7f]
                                            | _compMaskRight[2, ZeroFillRightShift(t0, 7) & 0x7f]
                                            | _compMaskRight[3, t0 & 0x7f]
                                            | _compMaskRight[4, ZeroFillRightShift(t1, 21) & 0x7f]
                                            | _compMaskRight[5, ZeroFillRightShift(t1, 14) & 0x7f]
                                            | _compMaskRight[6, ZeroFillRightShift(t1, 7) & 0x7f]
                                            | _compMaskRight[7, t1 & 0x7f];
            }
        }




        private void DesSetupSalt(int salt)
        {
            var saltbit = 1;
            var obit = 0x800000;
            for (var i = 0; i < 24; i++)
            {
              if ((salt & saltbit) > 0)
                _saltbits |= obit;
              saltbit <<= 1;
              obit >>= 1;
            }
        }


        private void DoDesEncryption()
        {
            int r;
            var count = 25;
            var f = 0;
            /* Don't bother with initial permutation. */
            var l = r = 0;

            while (count-- > 0)
            {
                /* Do each round. */
                var kl = 0;
                var kr = 0;
                var round = 16;

                while (round-- > 0)
                {
                    /* Expand R to 48 bits (simulate the E-box). */
                    var r48L = (long) (r & 0x00000001) << 23
                               | ZeroFillRightShift((r & 0xf8000000), 9)
                               | ZeroFillRightShift((r & 0x1f800000), 11)
                               | ZeroFillRightShift((r & 0x01f80000), 13)
                               | ZeroFillRightShift((r & 0x001f8000), 15);

                    var r48R = (long) (((long) r & 0x0001f800) << 7)
                               | (((long) r & 0x00001f80) << 5)
                               | (((long) r & 0x000001f8) << 3)
                               | (((long) r & 0x0000001f) << 1)
                               | ZeroFillRightShift(r & 0x80000000, 31);
                    /*
                     * Do salting for crypt() and friends, and
                     * XOR with the permuted key.
                     */
                    f = (int) ((r48L ^ r48R) & _saltbits);
                    r48L ^= f ^ _encryptionKeysLeft[kl++];
                    r48R ^= f ^ _encryptionKeysRight[kr++];
                    /*
                     * Do sbox lookups (which shrink it back to 32 bits)
                     * and do the pbox permutation at the same time.
                     */
                    f = (int) (_pSubstitionBoxes[0, _bitHandlingSubstitionBox[0, r48L >> 12]]
                               | _pSubstitionBoxes[1, _bitHandlingSubstitionBox[1, r48L & 0xfff]]
                               | _pSubstitionBoxes[2, _bitHandlingSubstitionBox[2, r48R >> 12]]
                               | _pSubstitionBoxes[3, _bitHandlingSubstitionBox[3, r48R & 0xfff]]);
                    /*
                     * Now that we've permuted things, complete f().
                     */
                    f ^= l;
                    l = r;
                    r = f;
                }

                r = l;
                l = f;
            }


            var i1 = _finalPermutationMaskLeft[0, ZeroFillRightShift(l, 24)];
            var i2 = _finalPermutationMaskLeft[1, ZeroFillRightShift(l, 16) & 0xff];
            var i3 = _finalPermutationMaskLeft[2, ZeroFillRightShift(l, 8) & 0xff];
            var i4 = _finalPermutationMaskLeft[3, l & 0xff];
            var i5 = _finalPermutationMaskLeft[4, ZeroFillRightShift(r, 24)];
            var i6 = _finalPermutationMaskLeft[5, ZeroFillRightShift(r, 16) & 0xff];
            var i7 = _finalPermutationMaskLeft[6, ZeroFillRightShift(r, 8) & 0xff];
            var i8 = _finalPermutationMaskLeft[7, r & 0xff];

            /* Final permutation (inverse of IP). */
            _desResult0 = i1
                          | i2
                          | i3
                          | i4
                          | i5
                          | i6
                          | i7
                          | i8;

            i1 = _finalPermutationMaskRight[0, ZeroFillRightShift(l, 24)];
            i2 = _finalPermutationMaskRight[1, ZeroFillRightShift(l, 16) & 0xff];
            i3 = _finalPermutationMaskRight[2, ZeroFillRightShift(l, 8) & 0xff];
            i4 = _finalPermutationMaskRight[3, l & 0xff];
            i5 = _finalPermutationMaskRight[4, ZeroFillRightShift(r, 24)];
            i6 = _finalPermutationMaskRight[5, ZeroFillRightShift(r, 16) & 0xff];
            i7 = _finalPermutationMaskRight[6, ZeroFillRightShift(r, 8) & 0xff];
            i8 = _finalPermutationMaskRight[7, r & 0xff];


            _desResult1 = i1
                          | i2
                          | i3
                          | i4
                          | i5
                          | i6
                          | i7
                          | i8;
        }

        private static long ZeroFillRightShift(long input, int shift)
        {
          if (shift == 0) return input;

          const int mask = 0x7fffffff;
          input >>= 1;
          input &= mask;
          input >>= shift - 1;
          return input;
        }

        private static int AsciiToBin(char ch)
        {
            // convert string to byte
            var lz = "z"[0];

            var la = "a"[0];
            var uz = "Z"[0];
            var ua = "A"[0];
            var ni = "9"[0];
            var dt = "."[0];

            if (ch > lz) return 0;
            if (ch >= la) return (ch - la + 38);
            if (ch > uz) return 0;
            if (ch >= ua) return (ch - ua + 12);
            if (ch > ni) return 0;
            if (ch >= dt) return (ch - dt);
            return 0;

        }

        public string Descrypt(string key, string salt_str)
        {
            var keybuf = new int[] {0, 0, 0, 0, 0, 0, 0, 0};
            var output = salt_str.Substring(0, 2);

            var q = 0;
            var keypos = 0;
            while (q < key.Length)
            {
              keybuf[q] = key[keypos] << 1;
              q++;
              if (keypos < key.Length - 1) keypos++;
            }

            DesSetKey(keybuf);

            /* This is the "old style" DES crypt. */
            var salt = AsciiToBin(salt_str[1]) << 6 |
                       AsciiToBin(salt_str[0]);
            DesSetupSalt(salt);
            DoDesEncryption();

            var l = (_desResult0 >> 8);
            output += Ascii64[(int) ZeroFillRightShift(l, 18) & 0x3f];
            output += Ascii64[(int) ZeroFillRightShift(l, 12) & 0x3f];
            output += Ascii64[(int) ZeroFillRightShift(l, 6) & 0x3f];
            output += Ascii64[(int) ZeroFillRightShift(l, 0) & 0x3f];

            l = (_desResult0 << 16) | ZeroFillRightShift(_desResult1, 16) & 0xffff;
            output += Ascii64[(int) ZeroFillRightShift(l, 18) & 0x3f];
            output += Ascii64[(int) ZeroFillRightShift(l, 12) & 0x3f];
            output += Ascii64[(int) ZeroFillRightShift(l, 6) & 0x3f];
            output += Ascii64[(int) ZeroFillRightShift(l, 0) & 0x3f];

            l = (_desResult1 << 2);
            output += Ascii64[(int) ZeroFillRightShift(l, 12) & 0x3f];
            output += Ascii64[(int) ZeroFillRightShift(l, 6) & 0x3f];
            output += Ascii64[(int) ZeroFillRightShift(l, 0) & 0x3f];

            return output;
          }

    }




}
