using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SERVER_SIDE_RSA
{
    class RSA_MODULE
    {
        RSACryptoServiceProvider csp;
        CORE_MODULE obj_core_module = new CORE_MODULE();

        public RSA_MODULE()
        {
            //Creating RSA Service Provider With definite length
            csp = new RSACryptoServiceProvider(obj_core_module.KEY_LENGTH);
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
            var obj_private_key = csp.ExportParameters(true);
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
            var pubKey = csp.ExportParameters(false);
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
}
