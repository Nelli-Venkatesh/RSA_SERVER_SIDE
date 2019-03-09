## .NET RSA AES SERVER SIDE LIBRARY FOR SECURE DATA TRANSMISSION

```markdown
This library used to send and recieve data in secure way from server to client side and client side to server.
For client side i have used angular JS services with Google Crypto JS and JsClasses for RSA. 
Using this library data can be transmitted both sides encrypted and in secure way.In the middle you can't access the data.
```
### Nuget Library : 
I Will update Nuget Library key shortly.
  You can find client side encryption and decryption in another github repository [CLIENT SIDE RSA WITH EXAMPLE SOLUTION](https://github.com/Venkatesh-Nelli/RSA_CLIENT_SIDE)
  
  
  ### Usage 
  Create a web api solution in the visual studio and in the Global.asax and in the Application_Start() initialize the library using ` CORE_MODULE.Initialize(4096);` line the number `4096` is the RSA encryption key length you can use different key lengths 4096,2048,1024,512.
  To Decrypt the data sent from the client in the controller just use the `string decoded_data = MAIN_MODULE.DECODE_DATA(data);` and in the string you'll get JSON data in the string.
  To Encrypt the data before sending it to client side use `string encrypted_data = MAIN_MODULE.ENCODE_DATA(decoded_data);` 
  
  ### Example
  ```markdown
    [HttpGet]
    [Route("get_Test")]
    public IHttpActionResult get_Test(string data)
    {
      string decoded_data = MAIN_MODULE.DECODE_DATA(data);
      string encrypted_data = MAIN_MODULE.ENCODE_DATA(decoded_data);
      return Ok(decoded_data);
    }

    [HttpPost]
    [Route("post_Test")]
    public IHttpActionResult post_Test(dynamic data)
    {
      string decoded_data = MAIN_MODULE.DECODE_DATA(data);
      string encrypted_data = MAIN_MODULE.ENCODE_DATA(decoded_data);
      return Ok(decoded_data);
    }
      
``` 
**FOR TOKEN GENERATION : **

[HttpGet]
[Route("get_token")]
public IHttpActionResult get_token()
{
  TOKEN_MODULE.addResponse("Success", "200");  //you can add many parameters with the access_token 
  return Ok(TOKEN_MODULE.generate_token());
}

**FOR PUBLIC AND PRIVATE KEY GENERATION : **

[HttpGet]
[Route("server_and_client_rsa_api")]
public IHttpActionResult server_and_client_rsa_api()
{
  return Ok(MAIN_MODULE.SERVER_CLIENT_RSA_PAIR());
}
  
  
### Support or Contact
For any issues in the code please raise an issue or mail me for any other information. 
