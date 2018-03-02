using System;

namespace DockerReigstryClientTest
{
    using System.Collections.Generic;
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
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;
    using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

    class Program
    {
        //Bearer realm="https://desktop-richq.captiveaire.com/AuthTest",service="Docker registry"

        static void Main(string[] args)
        {
            TestAsync().GetAwaiter().GetResult();            
            //TestAllAsync().GetAwaiter().GetResult();
            
            //SecurityAlgorithms.RsaSha256
        }

        //private static async Task TestAllAsync()
        //{
        //    var type = typeof(SecurityAlgorithms);

        //    var fields = type.GetFields();

        //    foreach (var field in fields)
        //    {
        //        var value = (string)field.GetValue(null);

        //        Console.WriteLine($"Attempting '{value}'...");

        //        try
        //        {
        //            await TestAsync(value);
        //        }
        //        catch (Exception ex)
        //        {
        //            Console.WriteLine($"  Failed: {ex.Message}");
        //        }
        //    }
        //}


        private static async Task TestAsync()
        {
            //const string uri = "http://172.22.5.74:5000/v2/";

            const string uri = "http://10.0.4.44:5000/v2/";

            var token = CreateToken();

            using (var httpClient = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Get, uri);

                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

                var response = await httpClient.SendAsync(request);

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    string content = await response.Content.ReadAsStringAsync();


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

            Console.WriteLine(cert.Thumbprint);

            X509Certificate bouncyCert = DotNetUtilities.FromX509Certificate(cert);

            AsymmetricKeyParameter bouncyPublicKey =  bouncyCert.GetPublicKey();

            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bouncyPublicKey);

            var encoded = info.GetDerEncoded();

            string kid;

            using (SHA256Managed sha256 = new SHA256Managed())
            {
                byte[] hash = sha256.ComputeHash(encoded);

                byte[] sub = hash
                    .Take(30)
                    .ToArray();

                string base32 = Base32.Encode(sub);

                //TODO: Just need to inser the colons and we're set.

                kid = base32;
            }
                
//            Console.WriteLine($"{data[0]:X}");

            kid = "HLYU:SELM:BG3X:EXTU:TWTV:ISOU:THVV:HNTF:VZ2E:YM3V:E7U2:PHKE";

            var key = new X509SecurityKey(cert)
            {
                KeyId = kid
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

        //private static string CreateJoseToken()
        //{

        //}

        //public static string BytesToBase32(byte[] bytes)
        //{
        //    const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        //    string output = "";
        //    for (int bitIndex = 0; bitIndex < bytes.Length * 8; bitIndex += 5)
        //    {
        //        int dualbyte = bytes[bitIndex / 8] << 8;
        //        if (bitIndex / 8 + 1 < bytes.Length)
        //            dualbyte |= bytes[bitIndex / 8 + 1];
        //        dualbyte = 0x1f & (dualbyte >> (16 - bitIndex % 8 - 5));
        //        output += alphabet[dualbyte];
        //    }

        //    return output;
        //}

        //public static byte[] Base32ToBytes(string base32)
        //{
        //    const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        //    List<byte> output = new List<byte>();
        //    char[] bytes = base32.ToCharArray();
        //    for (int bitIndex = 0; bitIndex < base32.Length * 5; bitIndex += 8)
        //    {
        //        int dualbyte = alphabet.IndexOf(bytes[bitIndex / 5]) << 10;
        //        if (bitIndex / 5 + 1 < bytes.Length)
        //            dualbyte |= alphabet.IndexOf(bytes[bitIndex / 5 + 1]) << 5;
        //        if (bitIndex / 5 + 2 < bytes.Length)
        //            dualbyte |= alphabet.IndexOf(bytes[bitIndex / 5 + 2]);

        //        dualbyte = 0xff & (dualbyte >> (15 - bitIndex % 5 - 8));
        //        output.Add((byte)(dualbyte));
        //    }
        //    return output.ToArray();
        //}
    }
}
