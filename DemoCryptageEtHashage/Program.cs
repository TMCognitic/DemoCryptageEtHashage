// Hashage - n'est pas réversible (MD5, SHA, SHA2)
using System.Security.Cryptography;
using System.Text;
using Tools.Crypto.Encryption.Symmetric;
using Tools.Crypto.Hashage;

namespace DemoCryptageEtHashage
{
    class Program
    {
        static void Main(string[] args)
        {
            string passwd = "Test1234=";

            //Hashage
            //SimpleHashSample(passwd);
            //SimpleHashSampleUsingTools(passwd);

            //Cryptage Symmetrique
            //byte[] key;
            //byte[] iv;
            //string aesCipher = SimpleAesEncryption(passwd, out key, out iv);
            //Console.WriteLine($"Mot de passe crypté : {aesCipher}");
            //string aesDecryptPasswd = SimpleAesDecryption(aesCipher, key, iv);
            //Console.WriteLine($"Mot de passe décrypté : {aesDecryptPasswd}");

            //Cryptage Symmetrique utilisant une boite à outils
            SimpleAesUsingTools(passwd);


            //Cryptage Asymmetrique
            //RSA rsa = RSA.Create(keySizeInBits: 2048);
            //string rsaCipher = SimpleRsaEncryption(passwd, rsa.ExportRSAPublicKey());
            //Console.WriteLine(rsaCipher);

            //string rsaDecryptPasswd = SimpleRsaDecryption(rsaCipher, rsa.ExportRSAPrivateKey());
            //Console.WriteLine($"Mot de passe décrypté : {rsaDecryptPasswd}");

            //SimpleRsaUsingTools(passwd);
        }

        static void SimpleHashSample(string password)
        {
            byte[] byteArray = Encoding.Default.GetBytes(password);

            //Algorithmes Disponible en C#
            //byte[] md5 = MD5.HashData(byteArray); //Déprécié à l'utilisation
            //byte[] sha1 = SHA1.HashData(byteArray); //Déprécié à l'utilisation
            //byte[] sha256 = SHA256.HashData(byteArray);
            //byte[] sha384 = SHA384.HashData(byteArray);
            //byte[] sha512 = SHA512.HashData(byteArray);
            //byte[] sha512bis = SHA512.HashData(byteArray);

            byte[] sha512 = SHA512.HashData(byteArray);
            string hashValue = Convert.ToBase64String(sha512);
            Console.WriteLine(hashValue);
        }
        static void SimpleHashSampleUsingTools(string password)
        {
            //Hash est une méthode d'extension
            string hashValue = password.Hash();
            Console.WriteLine(hashValue);
        }

        private static string SimpleAesEncryption(string passwd, out byte[] key, out byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    key = aes.Key;
                    iv = aes.IV;

                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        // By default, the StreamWriter uses UTF-8 encoding.
                        using (StreamWriter encryptWriter = new(cryptoStream, Encoding.Default))
                        {
                            encryptWriter.Write(passwd);
                        }

                        return Convert.ToBase64String(memoryStream.ToArray());
                    }
                }
            }
        }
        private static string SimpleAesDecryption(string cipher, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                using (MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(cipher)))
                {
                    aes.Key = key;
                    aes.IV = iv;

                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        // By default, the StreamWriter uses UTF-8 encoding.
                        using (StreamReader decryptReader = new StreamReader(cryptoStream, Encoding.Default))
                        {
                            return decryptReader.ReadToEnd();
                        }
                    }
                }
            }
        }
        private static void SimpleAesUsingTools(string passwd)
        {
            byte[] key = Array.Empty<byte>();
            byte[] iv = Array.Empty<byte>();

            AesEncryption aesEncryption = new AesEncryption();
            key = aesEncryption.Key;
            iv = aesEncryption.IV;

            string aesCipher = aesEncryption.Encrypt(passwd);
            Console.WriteLine($"Mot de passe crypté : {aesCipher}");

            aesEncryption = new AesEncryption(key, iv);
            string aesDecryptPasswd = aesEncryption.Decrypt(aesCipher);
            Console.WriteLine($"Mot de passe décrypté : {aesDecryptPasswd}");
        }
        private static string SimpleRsaEncryption(string passwd, byte[] publicKey)
        {
            RSA rsa = RSA.Create();
            rsa.ImportRSAPublicKey(publicKey, out int byteReads);
            byte[] toEncrypt = Encoding.Default.GetBytes(passwd);

            return Convert.ToBase64String(rsa.Encrypt(toEncrypt, RSAEncryptionPadding.Pkcs1));
        }
        private static string SimpleRsaDecryption(string cipher, byte[] privateKey)
        {
            RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKey, out int byteReads);
            //RSAParameters rsaKeyInfo = rsa.ExportParameters(true);
            privateKey = rsa.ExportRSAPrivateKey();
            rsa.ExportRSAPublicKey();

            byte[] toDecrypt = Convert.FromBase64String(cipher);

            return Encoding.Default.GetString(rsa.Decrypt(toDecrypt, RSAEncryptionPadding.Pkcs1));
        }

        //private static void SimpleRsaUsingTools(string passwd)
        //{
        //    throw new NotImplementedException();
        //}
    }
}

// Asymmetrique : Clé privée, clé publique (RSA)

