using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CEncryptor
{
    public static class StringCipher
    {
        private static List<string> aKeyPhrases = new List<string>
        {
            "E?QR+=Ey9cz)mJhhwE;tF'<JP\"5G&W",
            "RMk^V6LfKeq-nzbSa@9Wk6K_q+X2p^",
            "U8^gPcgd5-M=t=-4*g-9#aZekjABdy",
            "GMbx*Ra&c+vUv4LHCHy-mDY4G*6bwX",
            "NeUT2uu#HxXEGUh_uqT#?X^e$+bZzN",
            "D^C*bgyE!epu956tHQ&9DA6M%hSSEK",
            "rX_$SyV8H4SDbQhtnX&f#sZJTrh+u+",
            "b3V36hQ2ARchkCsztW#LTBfmHHKrSt",
            "SzXxU6KWT28a7_W*Q68L$EFY+=PyEx",
            "G9Sx5_+ry8+kpW-4s=Ba_EK64MhNj5",
            "Pm-rVse+=G-#Vgd7BSex&J*vUTn59j",
            "9UAC$5Rmufkeb&PsUs_-zSrq$kpe25",
            "!EfSaZQE6+Wvf=68XepyU#UY+Kd2vp",
            "aEnD2CyW^DAT$9eT?5j=gmz9XkhnvS",
            "htmbArcWqZd7ccdEx3m=p=ax+MRbC#",
            "=E$?5WxFqmw2%DgQ%qr&bwHW!Q@n9r",
            "C-6st*@a6z=&_pF9N@?2nAyR9xR_GC",
            "Py@MGRG_6$-76-3VV?x9V5mcjFQ#!p",
            "vkSZQF$3eamFCnx!s$hHgXMGvK+8pk",
            "AYd-#&4W-NYjrR-tTdHCLtF6PJuqL2",
            "Bm-8YKaG$a%bJe6gBumq2_z2E=#@mr",
            "d2G@kAwptn5#wrv4*B_?u$dZ6FZk-h",
            "GD4cf8%du$e2m@22c#2wxCFX6uFwaV",
            "8NR^D*WAd2?eam-Tja2CV8fuXv2nSQ",
            "$6zWcT64p2f6KBBf-$#@rLZ@j74Fk@",
            "=^tm^54xDBAdBMRTU*h?*S@_4BES4?",
            "+jagz9+AHX5&uMPtApHKz5c3&Hh^BJ",
            "Rc8v8JfFy&8XP34CeLw8wCh!x_86C$",
            "_uZMu-7TTH!9+*5*yE9v$Y&JpgNsfM",
            "ck8SM=c##%P*CQ9b2#Ne9?4g#26NeE",
            "wbBEM5=hng@Ed+6q=qz2NGYDY?Vk$b",
            "n_^D+n$Xf-77&D8waJgfcK!PwHD-Lc",
            "EWE!qLV+WWNuf5m*wGUeZDfGfd4UAp",
            "t-f@+TnbgrA7hAKN5!g=uBS-3Rj^md",
            "yRK@nzqm9-gx8@-uhxcVMQ67R+BU2?",
            "U3f7^7AeDv@E6UPZH?sz%s83G*#36v",
            "eYG%vR#PXg+xsD4f^$EFGDP+HhSNGH",
            "=h+Ln%%YcHTZEH@3ufL??NVdLzS^!4",
            "XQSQadkALp#Z&4pB9w@K_ruJF$VY*J",
            "w7+u%%H=zUxgs9uYwKf4FDVzvy4c9C",
            "_udz+#vcJ-pjDCE3LG7__LU#QL6W#Q",

        };
        // This constant is used to determine the keysize of the encryption algorithm in bits.
        // We divide this by 8 within the code below to get the equivalent number of bytes.
        private const int Keysize = 256;

        // This constant determines the number of iterations for the password bytes generation function.
        private const int DerivationIterations = 1000;

        public static string Encrypt(string plainText, string passPhrase)
        {
            //To add additional 50x work to "find" the password - we add one of defined random keyphrases to ensure it is long enaugh to make it safer
            Random r = new Random(DateTime.Now.Second);
            int rx = r.Next(0, aKeyPhrases.Count - 1);
            string rs = aKeyPhrases[rx];

            // Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
            // so that the same Salt and IV values can be used when decrypting.  
            var saltStringBytes = Generate256BitsOfRandomEntropy();
            var ivStringBytes = Generate256BitsOfRandomEntropy();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            var password = new Rfc2898DeriveBytes(rs+passPhrase, saltStringBytes, DerivationIterations);

            var keyBytes = password.GetBytes(Keysize / 8);
            using (var symmetricKey = new RijndaelManaged())
            {
                symmetricKey.BlockSize = 256;
                symmetricKey.Mode = CipherMode.CBC;
                symmetricKey.Padding = PaddingMode.PKCS7;
                using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                            cryptoStream.FlushFinalBlock();
                            // Create the final bytes as a concatenation of the random salt bytes, the random iv bytes and the cipher bytes.
                            var cipherTextBytes = saltStringBytes;
                            cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                            cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                            memoryStream.Close();
                            cryptoStream.Close();
                            return Convert.ToBase64String(cipherTextBytes);
                        }
                    }
                }
            }

        }

        public static string Decrypt(string cipherText, string passPhrase)
        {
            bool done = false;
            string s = "";
            foreach (string rs in aKeyPhrases)
            {
                try
                {
                    // Get the complete stream of bytes that represent:
                    // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
                    var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
                    // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
                    var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
                    // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
                    var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
                    // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
                    var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

                    var password = new Rfc2898DeriveBytes(rs+passPhrase, saltStringBytes, DerivationIterations);

                    var keyBytes = password.GetBytes(Keysize / 8);
                    using (var symmetricKey = new RijndaelManaged())
                    {
                        symmetricKey.BlockSize = 256;
                        symmetricKey.Mode = CipherMode.CBC;
                        symmetricKey.Padding = PaddingMode.PKCS7;
                        using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                        {
                            using (var memoryStream = new MemoryStream(cipherTextBytes))
                            {
                                using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                                {
                                    var plainTextBytes = new byte[cipherTextBytes.Length];
                                    var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                    memoryStream.Close();
                                    cryptoStream.Close();
                                    s = Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                                    done = true;
                                    
                                }
                            }
                        }
                    }
                    break;
                }
                catch
                {
                    //try next
                }
            }
            if (done)
                return s;
            else
                throw new Exception("Access denied");
        }

        private static byte[] Generate256BitsOfRandomEntropy()
        {
            var randomBytes = new byte[32]; // 32 Bytes will give us 256 bits.
            var rngCsp = new RNGCryptoServiceProvider();
            
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            
            return randomBytes;
        }
    }
}
