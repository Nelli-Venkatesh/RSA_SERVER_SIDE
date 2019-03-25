using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using System.Xml;

namespace SERVER_SIDE_RSA
{
    public static class CORE_MODULE
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

        //SERVER SIDE AES KEY PAIR FOR DATA ENCRYPTION WHEN SENDING RESPONSE WITH ENCRYPTION            
        public static string SERVER_SIDE_AES_KEY { get; set; }
        public static string SERVER_SIDE_AES_IV { get; set; }

        //SERVER SIDE TOKEN AES KEYS FOR TOKEN DATA ENCRYPTION
        public static string TOKEN_AES_KEY { get; set; }
        public static string TOKEN_AES_IV { get; set; }

        //TOKEN EXPIRY TIME SETUP
        public static int expiry_seconds { set; get; }
        public static int expiry_minutes { set; get; }
        public static int expiry_hours { set; get; }
        public static int expiry_days { set; get; }
        public static int expiry_months { set; get; }
        public static int expiry_year { set; get; }

        //TOKEN ISSUER AND AUDIENCE DATA
        public static string token_issuer { set; get; }
        public static string token_audience { set; get; }

        //TOKEN ROLES
        public static List<string> roles { get; set; }

        //TOKEN VERIFICATION OF ISSUER AND AUDIENCE
        public static string verify_issuer { get; set; }
        public static string verify_audience { get; set; }

        //RESPONSE PARAMETERS SENDING WITH TOKEN
        public static Dictionary<string, string> Response_Dictionary { get; set; }

        //INITIALIZATION OF ALL METHODS
        public static void Initialize(int KEY_LENGTH, string Audience = "", string Issuer = "")
        {
            //INITIALIZING KEY LENGTH
            CORE_MODULE.KEY_LENGTH = KEY_LENGTH;

            //GETTING PRIVATE KEY GENERATION FOR CLIENT SIDE PUBLIC KEY AND SERVER SIDE PRIVATE KEY
            string RSA_SERVER_parameters = RSA_MODULE.server_side_random_private_key_generator();

            //CREATION OF XML INSTANCE
            XmlDocument server_xml_doc = new XmlDocument();
            //LOADING STRING INTO XML
            server_xml_doc.LoadXml(RSA_SERVER_parameters);
            //SERILIZING XML DATA INTO JSON FORMAT
            string server_jsosn_text = JsonConvert.SerializeXmlNode(server_xml_doc);
            //deserialization of data using model
            RSA_Conversion_Model server_obj = JsonConvert.DeserializeObject<RSA_Conversion_Model>(server_jsosn_text);

            //setting parameters into server rsa parameter variables
            SERVER_EXPONENT = server_obj.RSAParameters.Exponent;
            SERVER_MODULES = server_obj.RSAParameters.Modulus;
            SERVER_P = server_obj.RSAParameters.P;
            SERVER_Q = server_obj.RSAParameters.Q;
            SERVER_D = server_obj.RSAParameters.D;
            SERVER_DP = server_obj.RSAParameters.DP;
            SERVER_DQ = server_obj.RSAParameters.DQ;
            SERVER_INVERSE_Q = server_obj.RSAParameters.InverseQ;


            //GETTING PRIVATE KEY GENERATION FOR SERVER SIDE PUBLIC KEY AND CLIENT SIDE PRIVATE KEY
            string RSA_CLIENT_parameters = RSA_MODULE.server_side_random_private_key_generator();
            //CREATION OF XML INSTANCE
            XmlDocument client_xml_doc = new XmlDocument();
            //LOADING STRING INTO XML
            client_xml_doc.LoadXml(RSA_CLIENT_parameters);
            //SERILIZING XML DATA INTO JSON FORMAT
            string client_jsosn_text = JsonConvert.SerializeXmlNode(client_xml_doc);
            RSA_Conversion_Model client_obj = JsonConvert.DeserializeObject<RSA_Conversion_Model>(client_jsosn_text);

            //setting parameters into client rsa parameter variables
            CLIENT_EXPONENT = client_obj.RSAParameters.Exponent;
            CLIENT_MODULES = client_obj.RSAParameters.Modulus;
            CLIENT_P = client_obj.RSAParameters.P;
            CLIENT_Q = client_obj.RSAParameters.Q;
            CLIENT_D = client_obj.RSAParameters.D;
            CLIENT_DP = client_obj.RSAParameters.DP;
            CLIENT_DQ = client_obj.RSAParameters.DQ;
            CLIENT_INVERSE_Q = client_obj.RSAParameters.InverseQ;

            //Unique number assigning as a key for AES_KEY and IV values of both SERVER SIDE AES and TOKEN Generation
            SERVER_SIDE_AES_KEY = EDITIONAL_METHODS.unique_code_generator(16);
            SERVER_SIDE_AES_IV = EDITIONAL_METHODS.unique_code_generator(16);

            TOKEN_AES_KEY = EDITIONAL_METHODS.unique_code_generator(16);
            TOKEN_AES_IV = EDITIONAL_METHODS.unique_code_generator(16);

            try
            {
                //Adding add responses to final response and assigning values
                Response_Dictionary = new Dictionary<string, string>();
                roles = new List<string>();
                token_issuer = Issuer;
                token_audience = Audience;
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(HttpStatusCode.BadRequest);
            }
        }

    }

    public static class RSA_MODULE
    {

        #region Server Key Generators

        //server side private key generation for decrypt data from client side
        public static string server_side_private_key_generator()
        {
            string final_string = string.Empty;
            final_string = @"<?xml version=""1.0"" encoding=""utf-16""?><RSAParameters xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">" +
                            "<Exponent>" + CORE_MODULE.SERVER_EXPONENT + "</Exponent>" +
                            "<Modulus>" + CORE_MODULE.SERVER_MODULES + "</Modulus>" +
                            "<P>" + CORE_MODULE.SERVER_P + "</P>" +
                            "<Q>" + CORE_MODULE.SERVER_Q + "</Q>" +
                            "<DP>" + CORE_MODULE.SERVER_DP + "</DP>" +
                            "<DQ>" + CORE_MODULE.SERVER_DQ + "</DQ>" +
                            "<InverseQ>" + CORE_MODULE.SERVER_INVERSE_Q + "</InverseQ>" +
                            "<D>" + CORE_MODULE.SERVER_D + "</D>" +
                            "</RSAParameters>";
            return final_string;
        }

        //server side public key generation for encrypt data before sending
        public static string server_side_public_key_generator()
        {
            string final_string = string.Empty;
            final_string = @"<?xml version=""1.0"" encoding=""utf-16""?><RSAParameters xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">" +
                            "<Exponent>" + CORE_MODULE.CLIENT_EXPONENT + "</Exponent>" +
                            "<Modulus>" + CORE_MODULE.CLIENT_MODULES + "</Modulus>" +
                            "</RSAParameters>";
            return final_string;
        }

        //random private key generation in xml format
        public static string server_side_random_private_key_generator()
        {
            //Creating RSA Service Provider With definite length
            RSACryptoServiceProvider OBJ_RSA_CRYPTO_SERVICE_PROVIDER = new RSACryptoServiceProvider(CORE_MODULE.KEY_LENGTH);
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

        //random public key generation in xml format
        public static string server_side_random_public_key_generation()
        {

            //Creating RSA Service Provider With definite length
            RSACryptoServiceProvider OBJ_RSA_CRYPTO_SERVICE_PROVIDER = new RSACryptoServiceProvider(CORE_MODULE.KEY_LENGTH);
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

        //client side private key generation for decrypt data to show in client
        public static string client_side_private_key_generator()
        {
            string final_string = string.Empty;
            final_string = @"<RSAKeyValue>" +
                            "<Exponent>" + CORE_MODULE.CLIENT_EXPONENT + "</Exponent>" +
                            "<Modulus>" + CORE_MODULE.CLIENT_MODULES + "</Modulus>" +
                            "<P>" + CORE_MODULE.CLIENT_P + "</P>" +
                            "<Q>" + CORE_MODULE.CLIENT_Q + "</Q>" +
                            "<DP>" + CORE_MODULE.CLIENT_DP + "</DP>" +
                            "<DQ>" + CORE_MODULE.CLIENT_DQ + "</DQ>" +
                            "<InverseQ>" + CORE_MODULE.CLIENT_INVERSE_Q + "</InverseQ>" +
                            "<D>" + CORE_MODULE.CLIENT_D + "</D>" +
                            "</RSAKeyValue>";
            return final_string;
        }

        //client side pubic key generation for encrypt data before sending to server
        public static string client_side_public_key_generator()
        {
            string final_string = string.Empty;
            final_string = @"<RSAKeyValue>" +
                            "<Exponent>" + CORE_MODULE.SERVER_EXPONENT + "</Exponent>" +
                            "<Modulus>" + CORE_MODULE.SERVER_MODULES + "</Modulus>" +
                            "</RSAKeyValue>";
            return final_string;
        }

        #endregion

        #region RSA Data Encryption

        //RSA data encryption using public key 
        public static string RSA_Encrypt(string plain_data, string public_key)
        {
            var RSA_CSP = new RSACryptoServiceProvider(CORE_MODULE.KEY_LENGTH);

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

        //RSA data decryption using private key
        public static string RSA_Decrypt(string encrypted_data, string private_key)
        {
            var RSA_CSP = new RSACryptoServiceProvider(CORE_MODULE.KEY_LENGTH);

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

        //data encryption using AES and return encrypted string
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

        //CORE AES Encryption Method
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

        //data decryption using AES and return decrypted string
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

        //CORE AES Decryption Method
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

    public static class EDITIONAL_METHODS
    {
        //To convert Base64URL into bytes conversion
        public static byte[] base64url_to_bytes_converter(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                                  .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

        //HMAC SHA256 hash generation
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

        //Unique number generation with required size
        public static string unique_code_generator(int maxSize)
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

        //string to base64 conversion
        public static string string_to_base64_conversion(string data)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(data);

            char[] padding = { '=' };

            string returnValue = System.Convert.ToBase64String(bytes)
            .TrimEnd(padding).Replace('+', '-').Replace('/', '_');
            return returnValue;
        }
    }

    public static class TOKEN_MODULE
    {
        //Token generation Method
        public static dynamic generate_token()
        {
            try
            {
                //Initializing Response Dictionary for returning token in json format with required parameters
                Dictionary<string, string> Response_Dictionary = new Dictionary<string, string>();
                //creating dynamic object
                dynamic objdata = new ExpandoObject();
                //adding issuing time 
                objdata.issued_time = DateTime.UtcNow;
                //adding expiry time
                objdata.expiry_time = TOKEN_MODULE.generate_expiry_time();
                //adding unique number for distinct token generation
                objdata.unique_number = EDITIONAL_METHODS.unique_code_generator(16);
                //adding issuer who issuing this token
                objdata.issuer = get_issuer();
                //adding audience who can use this token
                objdata.audience = get_audience();
                //adding roles who can access using this token
                List<string> value = get_user_roles();
                objdata.roles = value;
                //serializing dynamic object into json string 
                string token_data = JsonConvert.SerializeObject(objdata);
                //encrypt token json string using AES encryption
                string encrypted_value = AES_MODULE.AES_ENCRYPTION_DATA(token_data, CORE_MODULE.TOKEN_AES_KEY, CORE_MODULE.TOKEN_AES_IV);
                //adding generated token as access_token key pair value
                CORE_MODULE.Response_Dictionary.Add("access_token", encrypted_value);
                foreach (KeyValuePair<string, string> key_pair in CORE_MODULE.Response_Dictionary)
                {
                    Response_Dictionary.Add(key_pair.Key, key_pair.Value);
                }

                //clearing parameters
                CORE_MODULE.Response_Dictionary.Clear();
                CORE_MODULE.roles.Clear();

                return Response_Dictionary;
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(HttpStatusCode.BadRequest);
            }
        }

        public static string TOKEN_DECODE_DATA(string data)
        {
            string token_json_format = string.Empty;
            string final_output = string.Empty;

            //spliting string into string array 
            if (string.IsNullOrEmpty(data))
                throw new HttpResponseException(HttpStatusCode.NoContent);
            string[] values = data.Split('.');

            //assigning parameters
            string TOKEN = values[0].Replace(" ", "+");
            string RSA_ENCRYPTED_AES_KEY = values[1].Replace(" ", "+");
            string ENCRYPTED_DATA = values[2].Replace(" ", "+");
            try
            {
                //decrypting token to get token json string
                token_json_format = AES_MODULE.AES_DECRYPTION_DATA(TOKEN, CORE_MODULE.TOKEN_AES_KEY, CORE_MODULE.TOKEN_AES_IV);
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(HttpStatusCode.Unauthorized);

            }
            //converting json string into model object
            TOKEN_MODEL token_params = JsonConvert.DeserializeObject<TOKEN_MODEL>(token_json_format);
            //checking expiry time
            if (!expiry_time_check(token_params.EXPIRY_TIME))
                throw new HttpResponseException(HttpStatusCode.RequestTimeout);
            //checking roles
            if (!roles_check(token_params.ROLES, CORE_MODULE.roles))
                throw new HttpResponseException(HttpStatusCode.Unauthorized);
            //checking issuer
            if (!issuer_check(token_params.ISSUER))
                throw new HttpResponseException(HttpStatusCode.Unauthorized);
            //checking audience
            if (!audience_check(token_params.AUDIENCE))
                throw new HttpResponseException(HttpStatusCode.Unauthorized);

            try
            {
                //decrypting aes key pair for data decryption
                string AES_KEY_PAIR = RSA_MODULE.RSA_Decrypt(RSA_ENCRYPTED_AES_KEY, RSA_MODULE.server_side_private_key_generator());

                if (string.IsNullOrEmpty(AES_KEY_PAIR))
                    throw new HttpResponseException(HttpStatusCode.NoContent);

                //creating model object for key pair
                CLIEINT_AES_KEYS obj_AES = JsonConvert.DeserializeObject<CLIEINT_AES_KEYS>(AES_KEY_PAIR);

                //decryption of data using AES key pair
                final_output = AES_MODULE.AES_DECRYPTION_DATA(ENCRYPTED_DATA, obj_AES.KEY, obj_AES.IV);
                if (string.IsNullOrEmpty(final_output))
                    throw new HttpResponseException(HttpStatusCode.NoContent);

                CORE_MODULE.roles.Clear();

                //returning decrypted value
                return final_output;
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(HttpStatusCode.BadRequest);
            }
        }

        private static string generate_expiry_time()
        {
            string date = "";
            if (CORE_MODULE.expiry_seconds != 0)
                date = DateTime.UtcNow.AddSeconds(CORE_MODULE.expiry_seconds).ToString();
            else if (CORE_MODULE.expiry_minutes != 0)
                date = DateTime.UtcNow.AddMinutes(CORE_MODULE.expiry_minutes).ToString();
            else if (CORE_MODULE.expiry_hours != 0)
                date = DateTime.UtcNow.AddHours(CORE_MODULE.expiry_hours).ToString();
            else if (CORE_MODULE.expiry_days != 0)
                date = DateTime.UtcNow.AddDays(CORE_MODULE.expiry_days).ToString();
            else if (CORE_MODULE.expiry_months != 0)
                date = DateTime.UtcNow.AddMonths(CORE_MODULE.expiry_months).ToString();
            else if (CORE_MODULE.expiry_year != 0)
                date = DateTime.UtcNow.AddYears(CORE_MODULE.expiry_year).ToString();
            else
                date = DateTime.UtcNow.AddDays(1).ToString();
            return date;
        }

        private static bool expiry_time_check(string date)
        {
            DateTime expiry_date = DateTime.Parse(date);
            DateTime current_date = DateTime.UtcNow;
            int date_difference = Convert.ToInt32((expiry_date - current_date).TotalSeconds);
            if (date_difference > 0)
                return true;
            return false;
        }

        private static string get_audience()
        {
            if (string.IsNullOrEmpty(CORE_MODULE.token_audience))
                return "";
            else
                return CORE_MODULE.token_audience;
        }

        private static string get_issuer()
        {
            if (string.IsNullOrEmpty(CORE_MODULE.token_issuer))
                return "";
            else
                return CORE_MODULE.token_issuer;
        }

        private static dynamic get_user_roles()
        {
            if (CORE_MODULE.roles != null && CORE_MODULE.roles.Count > 0)
                return CORE_MODULE.roles;
            else
                return new List<string>();
        }

        private static void addRole(string role)
        {
            if (string.IsNullOrEmpty(role))
                throw new NoNullAllowedException("Input Data Not Found");
            else
                CORE_MODULE.roles.Add(role);
        }

        private static bool roles_check(List<string> roles, List<string> authorize_roles)
        {
            if (authorize_roles.Count < 1)
                return true;
            if (roles != null && roles.Count > 0)
            {
                for (int i = 0; i < roles.Count; i++)
                {
                    if (authorize_roles.Contains(roles[i]))
                        return true;
                }
                return false;
            }

            return false;
        }

        private static bool issuer_check(string issuer)
        {
            if (string.IsNullOrEmpty(issuer) || issuer == CORE_MODULE.verify_issuer)
                return true;
            return false;
        }

        private static bool audience_check(string audience)
        {
            if (string.IsNullOrEmpty(audience) || audience == CORE_MODULE.verify_audience)
                return true;
            return false;
        }

        public static void addResponse(string key, string value)
        {
            CORE_MODULE.Response_Dictionary.Add(key, value);
        }

        public static void addClaim(string claim)
        {
            addRole(claim);
        }

    }

    //Models for RSA Parameter Conversion
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
