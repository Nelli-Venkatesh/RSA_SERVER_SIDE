using System;
using System.Collections.Generic;
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

   
        public static string DECODE_DATA(string data)
        {
            try
            {
                string final_output = string.Empty;

                if (string.IsNullOrEmpty(data))
                    throw new HttpResponseException(HttpStatusCode.NoContent);
                string[] values = data.Split('.');

                byte[] buffer_1 = EDITIONAL_METHODS.base64url_to_bytes_converter(values[0]);
                string RSA_ENCRYPTED_AES_KEY = Encoding.UTF8.GetString(buffer_1).ToString();

                byte[] buffer_2 = EDITIONAL_METHODS.base64url_to_bytes_converter(values[1]);
                string ENCRYPTED_DATA = Encoding.UTF8.GetString(buffer_2).ToString();

                string AES_KEY_PAIR = RSA_MODULE.RSA_Decrypt(RSA_ENCRYPTED_AES_KEY, RSA_MODULE.server_side_private_key_generator());

                if (string.IsNullOrEmpty(AES_KEY_PAIR))
                    throw new HttpResponseException(HttpStatusCode.NoContent);

                CLIEINT_AES_KEYS obj_AES = JsonConvert.DeserializeObject<CLIEINT_AES_KEYS>(AES_KEY_PAIR);

                final_output = AES_MODULE.AES_DECRYPTION_DATA(ENCRYPTED_DATA, obj_AES.KEY, obj_AES.IV);
                if (string.IsNullOrEmpty(final_output))
                    throw new HttpResponseException(HttpStatusCode.NoContent);

                return final_output;
            }
            catch (Exception)
            {
                throw new HttpResponseException(HttpStatusCode.BadRequest);
            }
        }

        public static string ENCODE_DATA(string data)
        {
            try
            {
                string final_data = string.Empty;

                return final_data;
            }
            catch (Exception)
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


}
