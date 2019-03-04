using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace SERVER_SIDE_RSA
{
    public static class RSA_MODULE
    {
        public static int KEY_LENGTH { get; set; }

        //SERVER SIDE KEY GENERATORS 
        public static string SERVER_EXPONENT { get; set; }
        public static string SERVER_MODULES { get; set; }
        public static string SERVER_P { get; set; }
        public static string SERVER_Q { get; set; }
        public static string SERVER_D { get; set; }
        public static string SERVER_DP { get; set; }
        public static string SERVER_DQ { get; set; }
        public static string SERVER_INVERSE_Q { get; set; }

        //CLIENT SIDE KEY GENERATORS
        public static string CLIENT_EXPONENT { get; set; }
        public static string CLIENT_MODULES { get; set; }
        public static string CLIENT_P { get; set; }
        public static string CLIENT_Q { get; set; }
        public static string CLIENT_D { get; set; }
        public static string CLIENT_DP { get; set; }
        public static string CLIENT_DQ { get; set; }
        public static string CLIENT_INVERSE_Q { get; set; }

        public static string SERVER_SIDE_AES_KEY { get; set; }
        public static string SERVER_SIDE_AES_IV { get; set; }

        public static string CLIENT_SIDE_AES_KEY { get; set; }
        public static string CLIENT_SIDE_AES_IV { get; set; }

        public static void Initialize(int KEY_LENGTH)
        {
            RSA_MODULE.KEY_LENGTH = KEY_LENGTH;

            string RSA_SERVER_parameters = server_side_random_private_key_generator();
            XmlDocument server_xml_doc = new XmlDocument();
            server_xml_doc.LoadXml(RSA_SERVER_parameters);
            string server_jsosn_text = JsonConvert.SerializeXmlNode(server_xml_doc);
            RSA_Conversion_Model server_obj = JsonConvert.DeserializeObject<RSA_Conversion_Model>(server_jsosn_text);

            SERVER_EXPONENT = server_obj.RSAParameters.Exponent;
            SERVER_MODULES = server_obj.RSAParameters.Modulus;
            SERVER_P = server_obj.RSAParameters.P;
            SERVER_Q = server_obj.RSAParameters.Q;
            SERVER_D = server_obj.RSAParameters.D;
            SERVER_DP = server_obj.RSAParameters.DP;
            SERVER_DQ = server_obj.RSAParameters.DQ;
            SERVER_INVERSE_Q = server_obj.RSAParameters.InverseQ;

            string RSA_CLIENT_parameters = server_side_random_private_key_generator();
            XmlDocument client_xml_doc = new XmlDocument();
            client_xml_doc.LoadXml(RSA_CLIENT_parameters);
            string client_jsosn_text = JsonConvert.SerializeXmlNode(client_xml_doc);
            RSA_Conversion_Model client_obj = JsonConvert.DeserializeObject<RSA_Conversion_Model>(client_jsosn_text);

            CLIENT_EXPONENT = client_obj.RSAParameters.Exponent;
            CLIENT_MODULES = client_obj.RSAParameters.Modulus;
            CLIENT_P = client_obj.RSAParameters.P;
            CLIENT_Q = client_obj.RSAParameters.Q;
            CLIENT_D = client_obj.RSAParameters.D;
            CLIENT_DP = client_obj.RSAParameters.DP;
            CLIENT_DQ = client_obj.RSAParameters.DQ;
            CLIENT_INVERSE_Q = client_obj.RSAParameters.InverseQ;

            SERVER_SIDE_AES_KEY = EDITIONAL_METHODS.unique_number_generator(16);
            CLIENT_SIDE_AES_IV = EDITIONAL_METHODS.unique_number_generator(16);

        }


        #region Server Key Generators

        public static string server_side_private_key_generator()
        {
            string final_string = string.Empty;
            final_string = @"<?xml version=""1.0"" encoding=""utf-16""?><RSAParameters xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">" +
                            "<Exponent>" + SERVER_EXPONENT + "</Exponent>" +
                            "<Modulus>" + SERVER_MODULES + "</Modulus>" +
                            "<P>" + SERVER_P + "</P>" +
                            "<Q>" + SERVER_Q + "</Q>" +
                            "<DP>" + SERVER_DP + "</DP>" +
                            "<DQ>" + SERVER_DQ + "</DQ>" +
                            "<InverseQ>" + SERVER_INVERSE_Q + "</InverseQ>" +
                            "<D>" + SERVER_D + "</D>" +
                            "</RSAParameters>";
            return final_string;
        }

        public static string server_side_public_key_generator()
        {
            string final_string = string.Empty;
            final_string = @"<?xml version=""1.0"" encoding=""utf-16""?><RSAParameters xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">" +
                            "<Exponent>" + CLIENT_EXPONENT + "</Exponent>" +
                            "<Modulus>" + CLIENT_MODULES + "</Modulus>" +
                            "</RSAParameters>";
            return final_string;
        }

        public static string server_side_random_private_key_generator()
        {
            //Creating RSA Service Provider With definite length
            RSACryptoServiceProvider OBJ_RSA_CRYPTO_SERVICE_PROVIDER = new RSACryptoServiceProvider(KEY_LENGTH);
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

        public static string server_side_random_public_key_generation()
        {

            //Creating RSA Service Provider With definite length
            RSACryptoServiceProvider OBJ_RSA_CRYPTO_SERVICE_PROVIDER = new RSACryptoServiceProvider(KEY_LENGTH);
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

        #region Client Key Generators

        public static string client_side_private_key_generator()
        {
            string final_string = string.Empty;
            final_string = @"<RSAKeyValue>" +
                            "<Exponent>" + CLIENT_EXPONENT + "</Exponent>" +
                            "<Modulus>" + CLIENT_MODULES + "</Modulus>" +
                            "<P>" + CLIENT_P + "</P>" +
                            "<Q>" + CLIENT_Q + "</Q>" +
                            "<DP>" + CLIENT_DP + "</DP>" +
                            "<DQ>" + CLIENT_DQ + "</DQ>" +
                            "<InverseQ>" + CLIENT_INVERSE_Q + "</InverseQ>" +
                            "<D>" + CLIENT_D + "</D>" +
                            "</RSAKeyValue>";
            return final_string;
        }

        public static string client_side_public_key_generator()
        {
            string final_string = string.Empty;
            final_string = @"<RSAKeyValue>" +
                            "<Exponent>" + SERVER_EXPONENT + "</Exponent>" +
                            "<Modulus>" + SERVER_MODULES + "</Modulus>" +
                            "</RSAKeyValue>";
            return final_string;
        }

        #endregion

        #region RSA Data Encryption

        public static string RSA_Encrypt(string plain_data, string public_key)
        {
            var RSA_CSP = new RSACryptoServiceProvider(KEY_LENGTH);

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

        public static string RSA_Decrypt(string encrypted_data, string private_key)
        {
            var RSA_CSP = new RSACryptoServiceProvider(KEY_LENGTH);

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

    public static class AES_MODULE
    {
        #region AES ENCRYPTION

        public static string AES_ENCRYPTION_DATA(string data, string key_value, string iv_value)
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

        public static byte[] AES_Encryption(string plainText, byte[] key, byte[] iv)
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

        public static string AES_DECRYPTION_DATA(string data, string key_value, string iv_value)
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

        public static string AES_Decryption(byte[] cipherText, byte[] key, byte[] iv)
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

    public static class EDITIONAL_METHODS
    {
        public static byte[] base64url_to_bytes_converter(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                                  .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

        public static string HMAC_SHA256(string message, string key)
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

        public static string unique_number_generator(int maxSize)
        {
            char[] chars = new char[62];
            chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
            byte[] data = new byte[1];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetNonZeroBytes(data);
                data = new byte[maxSize];
                crypto.GetNonZeroBytes(data);
            }
            StringBuilder result = new StringBuilder(maxSize);
            foreach (byte b in data)
            {
                result.Append(chars[b % (chars.Length)]);
            }
            return result.ToString();
        }


    }

    public class RSA_Conversion_Model
    {
        public RSA_Parameters RSAParameters { get; set; }
    }
    public class RSA_Parameters
    {
        public string Exponent { get; set; }
        public string Modulus { get; set; }
        public string P { get; set; }
        public string Q { get; set; }
        public string DP { get; set; }
        public string DQ { get; set; }
        public string D { get; set; }
        public string InverseQ { get; set; }
    }
}
