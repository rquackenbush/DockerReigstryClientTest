using System;

namespace DockerReigstryClientTest
{
    using System.IdentityModel.Tokens.Jwt;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Albireo.Base32;
    using Microsoft.IdentityModel.Tokens;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;
    using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

    class Program
    {
        static void Main(string[] args)
        {
            TestAsync().GetAwaiter().GetResult();            
        }

        private static async Task TestAsync()
        {
            const string requestUri = "http://10.0.4.44:5000/v2/";

            var token = CreateToken();

            using (var httpClient = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Get, requestUri);

                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

                var response = await httpClient.SendAsync(request);

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    string content = await response.Content.ReadAsStringAsync();

                    Console.WriteLine(content);

                    Console.WriteLine("  Woot!");
                }
                else if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    Console.WriteLine("  Shizer.");
                }
                else
                {
                    Console.WriteLine("  What the hell???");
                }
            }
        }

        private static string CreateToken()
        {
            //Load up the pulic / private key
            var bytes = File.ReadAllBytes("registry-auth.pfx");

            X509Certificate2 cert = new X509Certificate2(bytes, new SecureString());

            var key = new X509SecurityKey(cert)
            {
                KeyId = GetKid(cert)
            };

            var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
            
            var header = new JwtHeader(credentials);

            var claims = new Claim[]
            {
                //new Claim("scope", "agent:"),
            };

            DateTime expires = DateTime.UtcNow.Add(TimeSpan.FromDays(100));
            DateTime notBefore = DateTime.UtcNow.Subtract(TimeSpan.FromMinutes(30));
            DateTime issuedAt = DateTime.UtcNow;

            var payload = new JwtPayload("issuer", "Docker registry", claims, notBefore, expires, issuedAt);

            var secToken = new JwtSecurityToken(header, payload);

            var handler = new JwtSecurityTokenHandler();

            var token = handler.WriteToken(secToken);

            return token;
        }

        /// <summary>
        /// Gets the kid for docker registry.
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        private static string GetKid(X509Certificate2 certificate)
        {
            X509Certificate bouncyCert = DotNetUtilities.FromX509Certificate(certificate);

            AsymmetricKeyParameter bouncyPublicKey = bouncyCert.GetPublicKey();

            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bouncyPublicKey);

            var encoded = info.GetDerEncoded();

            using (SHA256Managed sha256 = new SHA256Managed())
            {
                byte[] hash = sha256.ComputeHash(encoded);

                //Take the first 30 bytes
                byte[] sub = hash
                    .Take(30)
                    .ToArray();

                string base32 = Base32.Encode(sub);

                return FormatKid(base32);
            }
        }

        private static string FormatKid(string raw)
        {
            const int RawKidLength = 48;

            if (raw.Length != RawKidLength)
                throw new Exception($"Raw kid was {raw.Length} characters instead of {RawKidLength}.");

            string[] parts =
            {
                raw.Substring(0, 4),
                raw.Substring(4, 4),
                raw.Substring(8, 4),
                raw.Substring(12, 4),
                raw.Substring(16, 4),
                raw.Substring(20, 4),
                raw.Substring(24, 4),
                raw.Substring(28, 4),
                raw.Substring(32, 4),
                raw.Substring(36, 4),
                raw.Substring(40 , 4),
                raw.Substring(44, 4),
            };

            return string.Join(':', parts);

        }
    }
}
