using System;
using System.Collections.Generic;
using System.Data;
using System.Dynamic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using Newtonsoft.Json;
namespace SERVER_SIDE_RSA
{
    public static class MAIN_MODULE
    {
        public static SERVER_CLIENT_RSA_KEYS SERVER_CLIENT_RSA_PAIR()
        {
            SERVER_CLIENT_RSA_KEYS obj = new SERVER_CLIENT_RSA_KEYS();
            obj.CLIENT_PRIVATE_KEY = RSA_MODULE.client_side_private_key_generator();
            obj.CLIENT_PUBLIC_KEY = RSA_MODULE.client_side_public_key_generator();
            return obj;
        }
    
        public static string DECODE_DATA(string data)
        {
            try
            {
                string final_output = string.Empty;

                if (string.IsNullOrEmpty(data))
                    throw new HttpResponseException(HttpStatusCode.NoContent);
                string[] values = data.Split('.');

                //byte[] buffer_1 = EDITIONAL_METHODS.base64url_to_bytes_converter(values[0]);
                //string RSA_ENCRYPTED_AES_KEY = Encoding.UTF8.GetString(buffer_1).ToString();

                //byte[] buffer_2 = EDITIONAL_METHODS.base64url_to_bytes_converter(values[1]);
                //string ENCRYPTED_DATA = Encoding.UTF8.GetString(buffer_2).ToString();

                string RSA_ENCRYPTED_AES_KEY = values[0].Replace(" ", "+");
                string ENCRYPTED_DATA = values[1].Replace(" ", "+");


                string AES_KEY_PAIR = RSA_MODULE.RSA_Decrypt(RSA_ENCRYPTED_AES_KEY, RSA_MODULE.server_side_private_key_generator());

                if (string.IsNullOrEmpty(AES_KEY_PAIR))
                    throw new HttpResponseException(HttpStatusCode.NoContent);

                CLIEINT_AES_KEYS obj_AES = JsonConvert.DeserializeObject<CLIEINT_AES_KEYS>(AES_KEY_PAIR);

                final_output = AES_MODULE.AES_DECRYPTION_DATA(ENCRYPTED_DATA, obj_AES.KEY, obj_AES.IV);
                if (string.IsNullOrEmpty(final_output))
                    throw new HttpResponseException(HttpStatusCode.NoContent);

                return final_output;
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(HttpStatusCode.BadRequest);
            }
        }

        public static string ENCODE_DATA(string data)
        {
            try
            {

                string final_data = string.Empty;
                string ENCRYPTED_DATA = AES_MODULE.AES_ENCRYPTION_DATA(data, CORE_MODULE.SERVER_SIDE_AES_KEY, CORE_MODULE.SERVER_SIDE_AES_IV);

                CLIEINT_AES_KEYS obj = new CLIEINT_AES_KEYS();
                obj.KEY = CORE_MODULE.SERVER_SIDE_AES_KEY;
                obj.IV = CORE_MODULE.SERVER_SIDE_AES_IV;
                string AES_ENCRYPTIN_KEY_PAIR = JsonConvert.SerializeObject(obj);

                string RSA_ENCRYPTED_KEY_PAIR = RSA_MODULE.RSA_Encrypt(AES_ENCRYPTIN_KEY_PAIR, RSA_MODULE.server_side_public_key_generator());
                final_data = RSA_ENCRYPTED_KEY_PAIR + "." + ENCRYPTED_DATA;
                return final_data;
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(HttpStatusCode.BadRequest);
            }
        } 
    }

    public class CLIEINT_AES_KEYS
    {
        public string KEY { get; set; }
        public string IV { get; set; }
    }

    public class SERVER_CLIENT_RSA_KEYS
    {
        public string CLIENT_PUBLIC_KEY { get; set; }
        public string CLIENT_PRIVATE_KEY { get; set; }
    }

    public class TOKEN_MODEL
    {
        public string ISSUED_TIME { get; set; }
        public string EXPIRY_TIME { get; set; }
        public string UNIQUE_NUMBER { get; set; }
        public string ISSUER { get; set; }
        public string AUDIENCE { get; set; }
        public List<string> ROLES { get; set; }

    }

}
