using System;

namespace DockerReigstryClientTest
{
    using System.IdentityModel.Tokens.Jwt;
    using System.IO;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security;
    using System.Security.Claims;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Microsoft.IdentityModel.Tokens;

    class Program
    {
        //Bearer realm="https://desktop-richq.captiveaire.com/AuthTest",service="Docker registry"

        static void Main(string[] args)
        {
           TestAsync().GetAwaiter().GetResult();            
        }


        private static async Task TestAsync()
        {
            const string uri = "http://172.22.5.74:5000/v2/";

            var token = CreateToken();

            using (var httpClient = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Get, uri);

                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

                var response = await httpClient.SendAsync(request);

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    Console.WriteLine("Woot!");
                }
                else
                {
                    Console.WriteLine("Shizer.");
                }
            }
        }

        private static string CreateToken()
        {
            //https://www.codeproject.com/Tips/1208535/Create-And-Consume-JWT-Tokens-in-csharp

            //Load up the pulic / private key
            var bytes = File.ReadAllBytes("registry-auth.pfx");

            X509Certificate2 cert = new X509Certificate2(bytes, new SecureString());

            Console.WriteLine(cert.Thumbprint);

            var key = new X509SecurityKey(cert);

            var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature);

            var header = new JwtHeader(credentials);

            var claims = new Claim[]
            {
                new Claim("scope", "agent:"),
            };

            DateTime expires = DateTime.UtcNow.Add(TimeSpan.FromDays(100));
            DateTime notBefore = DateTime.UtcNow.Subtract(TimeSpan.FromMinutes(30));
            //DateTime? notBefore = null;
            DateTime issuedAt = DateTime.UtcNow;

            var payload = new JwtPayload("issuer", "Docker registry", claims, notBefore, expires, issuedAt);

            var secToken = new JwtSecurityToken(header, payload);

            var handler = new JwtSecurityTokenHandler();

            var token = handler.WriteToken(secToken);

            return token;
        }
    }
}
