using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace EPICAPI.AppTest
{
    public class Program
    {
        static void Main(string[] args)
        {
            // Get the access token
            var bearerToken = new GetBearerToken();
            string accessToken = bearerToken.Authorize();

            // Use the access token to fetch patient data
            var patientInfo = new GetPatientInfo();
            // Wait for the GetPatientData method to complete
            new GetPatientInfo().GetPatientData(accessToken).Wait();
        }
    }

    public class GetPatientInfo
    {
        public async Task GetPatientData(string accessToken)
        {
            if (!string.IsNullOrEmpty(accessToken))
            {
                using (var client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                    // Example FHIR endpoint for reading a specific patient resource
                    string endpoint = "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/Patient/erXuFYUfucBZaryVksYEcMg3";

                    HttpResponseMessage response = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, endpoint));

                    if (response.IsSuccessStatusCode)
                    {
                        string responseBody = await response.Content.ReadAsStringAsync();
                        if (!string.IsNullOrEmpty(responseBody))
                        {
                            try
                            {
                                Console.WriteLine(responseBody); // You can process the patient data here
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"Failed to process response JSON: {ex.Message}");
                            }
                        }
                        else
                        {
                            Console.WriteLine("Empty response.");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Failed to read patient data. Status code: {response.StatusCode}");
                    }
                }
            }
            else
            {
                Console.WriteLine("Failed to obtain access token.");
            }
        }
    }

    public class GetBearerToken
    {
        public string Authorize()
        {
            string privateKeyXml = "<RSAKeyValue>Add your Key here</RSAKeyValue>";

            var jwtCreator = new CreateJwt();
            string token = jwtCreator.Jwt(privateKeyXml);

            try
            {
                HttpClient client = new HttpClient();
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token");

                var values = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    new KeyValuePair<string, string>("client_assertion", token)
                };

                FormUrlEncodedContent content = new FormUrlEncodedContent(values);
                request.Content = content;

                HttpResponseMessage response = client.SendAsync(request).Result;

                response.EnsureSuccessStatusCode();
                string result = response.Content.ReadAsStringAsync().Result;
                // Locate the start of the access_token value
                int tokenStartIndex = result.IndexOf("\"ey")+1;

                // Locate the end of the access_token value
                int tokenEndIndex = result.IndexOf("\",", tokenStartIndex);

                // Extract the token
                string accessToken = result.Substring(tokenStartIndex, tokenEndIndex - tokenStartIndex);

                Console.WriteLine("In here" + accessToken);
                return accessToken;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                Console.WriteLine(new System.Diagnostics.StackTrace().ToString());
                return string.Empty;
            }
        }
    }

    public class CreateJwt
    {
        static RSAParameters ReadPrivateKeyFromString(string privateKey)
        {
            try
            {
                RSAParameters rsaParameters = new RSAParameters();

                // Load RSA key from XML string
                using (var reader = new StringReader(privateKey))
                {
                    XmlDocument xmlDoc = new XmlDocument();
                    xmlDoc.Load(reader);

                    // Get RSA parameters from XML
                    rsaParameters.Modulus = Convert.FromBase64String(xmlDoc.SelectSingleNode("//Modulus").InnerText);
                    rsaParameters.Exponent = Convert.FromBase64String(xmlDoc.SelectSingleNode("//Exponent").InnerText);
                    rsaParameters.P = Convert.FromBase64String(xmlDoc.SelectSingleNode("//P").InnerText);
                    rsaParameters.Q = Convert.FromBase64String(xmlDoc.SelectSingleNode("//Q").InnerText);
                    rsaParameters.DP = Convert.FromBase64String(xmlDoc.SelectSingleNode("//DP").InnerText);
                    rsaParameters.DQ = Convert.FromBase64String(xmlDoc.SelectSingleNode("//DQ").InnerText);
                    rsaParameters.InverseQ = Convert.FromBase64String(xmlDoc.SelectSingleNode("//InverseQ").InnerText);
                    rsaParameters.D = Convert.FromBase64String(xmlDoc.SelectSingleNode("//D").InnerText);
                }

                return rsaParameters;
            }
            catch (Exception e)
            {
                Console.WriteLine("Error parsing private key: " + e.Message);
                throw;
            }
        }

        public string Jwt(string privateKey)
        {
            RSA rsa = RSA.Create();
            rsa.ImportParameters(ReadPrivateKeyFromString(privateKey));

            var now = DateTime.UtcNow;
            var gJti = Guid.NewGuid();

            // Build the JWT token
            string header = "{\"alg\":\"RS384\",\"typ\":\"JWT\"}";
            string payload = "{\"sub\":\"b96b1519-ac36-43dc-af0d-293c48f5db9f\",\"aud\":\"https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token\",\"iss\":\"b96b1519-ac36-43dc-af0d-293c48f5db9f\",\"jti\":\"" + gJti.ToString() + "\",\"iat\":" + new DateTimeOffset(now).ToUnixTimeSeconds() + ",\"exp\":" + new DateTimeOffset(now.AddMinutes(4)).ToUnixTimeSeconds() + ",\"nbf\":" + new DateTimeOffset(now).ToUnixTimeSeconds() + "}";

            var headerBytes = Encoding.UTF8.GetBytes(header);
            var payloadBytes = Encoding.UTF8.GetBytes(payload);

            var segments = new[]
            {
                Base64UrlEncode(headerBytes),
                Base64UrlEncode(payloadBytes)
            };

            var signingInput = string.Join(".", segments);

            var signature = rsa.SignData(Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
            var encodedSignature = Base64UrlEncode(signature);

            return $"{signingInput}.{encodedSignature}";
        }

        private string Base64UrlEncode(byte[] input)
        {
            string base64 = Convert.ToBase64String(input);
            base64 = base64.Split('=')[0];  // Remove the padding '=' characters
            base64 = base64.Replace('+', '-');  // Replace URL-unsafe characters
            base64 = base64.Replace('/', '_');  // Replace URL-unsafe characters
            return base64;
        }
    }
}
