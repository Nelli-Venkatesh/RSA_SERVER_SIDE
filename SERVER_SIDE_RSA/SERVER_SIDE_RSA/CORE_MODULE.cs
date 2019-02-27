using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SERVER_SIDE_RSA
{
    class RSA_MODULE
    {
        RSACryptoServiceProvider OBJ_RSA_CRYPTO_SERVICE_PROVIDER;
        MAIN_MODULE obj_core_module = new MAIN_MODULE();

        public RSA_MODULE()
        {
            //Creating RSA Service Provider With definite length
            OBJ_RSA_CRYPTO_SERVICE_PROVIDER = new RSACryptoServiceProvider(obj_core_module.KEY_LENGTH);
        }

        #region  Key Generators

        public string private_key_generator()
        {
            string final_string = string.Empty;
            final_string = @"<?xml version=""1.0"" encoding=""utf-16""?><RSAParameters xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">" +
                            "<Exponent>" + obj_core_module.EXPONENT + "</Exponent>" +
                            "<Modulus>" + obj_core_module.MODULES + "</Modulus>" +
                            "<P>" + obj_core_module.P + "</P>" +
                            "<Q>" + obj_core_module.Q + "</Q>" +
                            "<DP>" + obj_core_module.DP + "</DP>" +
                            "<DQ>" + obj_core_module.DQ + "</DQ>" +
                            "<InverseQ>" + obj_core_module.INVERSE_Q + "</InverseQ>" +
                            "<D>" + obj_core_module.D + "</D>" +
                            "</RSAParameters>";
            return final_string;
        }

        public string public_key_generator()
        {
            string final_string = string.Empty;
            final_string = @"<?xml version=""1.0"" encoding=""utf-16""?><RSAParameters xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">" +
                            "<Exponent>" + obj_core_module.EXPONENT + "</Exponent>" +
                            "<Modulus>" + obj_core_module.MODULES + "</Modulus>" +
                            "</RSAParameters>";
            return final_string;
        }

        public string random_private_key_generator()
        {
            //Ceating the private key Instance
            var obj_private_key = OBJ_RSA_CRYPTO_SERVICE_PROVIDER.ExportParameters(true);
            //Creating Instance for String Writer
            var sw = new System.IO.StringWriter();
            //Creating Instance for XML Serialization
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //serialize the key into the stream
            xs.Serialize(sw, obj_private_key);
            //Converting stream into string 
            return sw.ToString();
        }

        public string random_public_key_generation()
        {
            //Ceating the public key Instance
            var pubKey = OBJ_RSA_CRYPTO_SERVICE_PROVIDER.ExportParameters(false);
            //Creating Instance for String Writer
            var sw = new System.IO.StringWriter();
            //Creating Instance for XML Serialization
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //serialize the key into the stream
            xs.Serialize(sw, pubKey);
            //Converting stream into string 
            return sw.ToString();
        }

        #endregion

        #region RSA Data Encryption

        public string RSA_Encrypt(string plain_data, string public_key)
        {
            var RSA_CSP = new RSACryptoServiceProvider(obj_core_module.KEY_LENGTH);

            //converting public key from string format to RSA Parameter
            var new_public_final_key = new RSAParameters();
            {
                //conversion into from string 
                var sr = new System.IO.StringReader(public_key);
                //Creation Of object for RSA Serializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //Deserializing into RSA Paramerter 
                new_public_final_key = (RSAParameters)xs.Deserialize(sr);
            }

            //Loadig the public key to object
            RSA_CSP = new RSACryptoServiceProvider();
            RSA_CSP.ImportParameters(new_public_final_key);

            //Convertion data into UTF-8 Format
            var bytes_plain_text = System.Text.Encoding.UTF8.GetBytes(plain_data);

            //applying pkcs#2.0 padding and encryption of data 
            var bytes_chiper_text = RSA_CSP.Encrypt(bytes_plain_text, true);

            //Conversion Of data bytes array into base64 string 
            var plain_text = Convert.ToBase64String(bytes_chiper_text);

            return plain_text;

        }

        #endregion

        #region RSA Data Decryption

        public string RSA_Decrypt(string encrypted_data, string private_key)
        {
            var RSA_CSP = new RSACryptoServiceProvider(obj_core_module.KEY_LENGTH);

            //converting private key from string format to RSA Parameter
            var new_private_final_key = new RSAParameters();
            {
                //conversion into from string 
                var sr = new System.IO.StringReader(private_key);
                //Creation Of object for RSA Serializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //Deserializing into RSA Paramerter 
                new_private_final_key = (RSAParameters)xs.Deserialize(sr);
            }

            //Converting data into base64 string 
            var bytes_chiper_text = Convert.FromBase64String(encrypted_data);

            //Loadig the public key to object
            RSA_CSP = new RSACryptoServiceProvider();
            RSA_CSP.ImportParameters(new_private_final_key);

            //applying pkcs#2.0 padding and Decryption of data 
            var bytes_plain_text = RSA_CSP.Decrypt(bytes_chiper_text, true);

            //Conversion Of data bytes array into UTF-8 Format string 
            string plain_text = System.Text.Encoding.UTF8.GetString(bytes_plain_text);

            return plain_text;

        }

        #endregion

    }

    class AES_MODULE
    {
        #region AES ENCRYPTION

        public string AES_ENCRYPTION_DATA(string data, string key_value, string iv_value)
        {

            if (data == null || data.Length <= 0)
            {
                throw new ArgumentNullException("Input Data Is Null");
            }
            if (key_value == null || key_value.Length <= 0)
            {
                throw new ArgumentNullException("Key Value Is Null");
            }
            if (iv_value == null || iv_value.Length <= 0)
            {
                throw new ArgumentNullException("IV Value Is Null");
            }

            //Converting Variables into UTF-8 Format
            var bytes_key = Encoding.UTF8.GetBytes(key_value);
            var bytes_iv = Encoding.UTF8.GetBytes(iv_value);

            //Encryption Method
            var bytes_encrypted_data = AES_Encryption(data, bytes_key, bytes_iv);
            return Convert.ToBase64String(bytes_encrypted_data);
        }

        private static byte[] AES_Encryption(string plainText, byte[] key, byte[] iv)
        {

            byte[] encrypted;

            // Creating a RijndaelManaged object with the specified key and IV.
            using (var rijAlg = new RijndaelManaged())
            {
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.FeedbackSize = 128;
                rijAlg.Key = key;
                rijAlg.IV = iv;

                //Creating Encryption Object 
                var bytes_encrption_object = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);


                // Creating the streams used for encryption.
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, bytes_encrption_object, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Writes all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        #endregion

        #region AES DECRYPTION

        public string AES_DECRYPTION_DATA(string data, string key_value, string iv_value)
        {
            if (data == null || data.Length <= 0)
            {
                throw new ArgumentNullException("Input Data Is Null");
            }
            if (key_value == null || key_value.Length <= 0)
            {
                throw new ArgumentNullException("Key Value Is Null");
            }
            if (iv_value == null || iv_value.Length <= 0)
            {
                throw new ArgumentNullException("IV Value Is Null");
            }

            var encrypted_data = Convert.FromBase64String(data);

            //Converting Variables into UTF-8 Format
            var bytes_key = Encoding.UTF8.GetBytes(key_value);
            var bytes_iv = Encoding.UTF8.GetBytes(iv_value);

            //Decryption Method
            var decrypted_data = AES_Decryption(encrypted_data, bytes_key, bytes_iv);
            return decrypted_data;
        }

        private static string AES_Decryption(byte[] cipherText, byte[] key, byte[] iv)
        {

            string plaintext = null;

            // Creating a RijndaelManaged object with the specified key and IV.
            using (var rijAlg = new RijndaelManaged())
            {
                //Settings
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.FeedbackSize = 128;
                rijAlg.Key = key;
                rijAlg.IV = iv;

                //Creating Decryption Object 
                var bytes_decrption_object = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Creating the streams used for decryption.
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, bytes_decrption_object, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        #endregion
    }

    class EDITIONAL_METHODS
    {
        private static byte[] base64url_to_bytes_converter(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                                  .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }
        private static string HMAC_SHA256(string message, string key)
        {
            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = encoding.GetBytes(key);
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hashmessage);
            }
        }

    }

}
