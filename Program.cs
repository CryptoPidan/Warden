using System.Net;
using System.Net.Http.Headers;
using Nethereum.Signer;
using Newtonsoft.Json;

namespace Warden
{
    internal class Program
    {
        public static readonly object _lock = new();
        public static readonly object _dataLock = new();
        public static List<AccountInfo> AccountInfoList = [];
        public static readonly Dictionary<int, Dictionary<string, string>> DataMatrix = [];
        public static string CaptchaKey = string.Empty;
        public static string CaptchaURL = "https://api.1captcha.vip";
        
        static async Task Main()
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            LoadPrivateKeyAndProxyAndLog();
            DateTime lastExportTime = DateTime.Now;
            while (true)
            {
                foreach (var account in AccountInfoList)
                {
                    if (DateTime.Now >= account.NextExecutionTime)
                    {
                        try
                        {
                            await Script(account);
                            account.NextExecutionTime = DateTime.Now.AddMinutes(1445);
                            account.FailTime = 0;
                        }
                        catch (Exception ex)
                        {
                            if (account.FailTime < 15)
                                account.FailTime += 1;
                            account.NextExecutionTime = DateTime.Now.AddSeconds(Math.Pow(2, account.FailTime));
                            ShowMsg($"执行异常(第{account.FailTime}次): {ex.Message}", 3);
                        }
                        Thread.Sleep(5000);
                    }
                    if ((DateTime.Now - lastExportTime).TotalMinutes >= 10)
                    {
                        ExportDataMatrixToCsv();
                        lastExportTime = DateTime.Now;
                    }
                }
                Thread.Sleep(1000);
            }
        }
        public static async Task<string> Captcha_Cloudflare()
        {
            HttpClientHandler httpClientHandler = new();
            HttpClient client = new(httpClientHandler);
            HttpRequestMessage request = new(HttpMethod.Post, CaptchaURL+"/createTask");
            var websiteURL = "https://app.wardenprotocol.org/auth";
            var websiteKey = "0x4AAAAAAAM8ceq5KhP1uJBt";
            var payload = new
            {
                clientKey = CaptchaKey,
                task = new
                {
                    type = "TurnstileTaskProxyless",
                    websiteURL,
                    websiteKey
                },
                softID = 56910
            };
            var payloadJson = JsonConvert.SerializeObject(payload);
            request.Content = new StringContent(payloadJson);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            HttpResponseMessage response = await client.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();
            try
            {
                response.EnsureSuccessStatusCode();
            }
            catch (HttpRequestException ex)
            {
                throw (new Exception($"{ex.Message}\n响应内容: {(string.IsNullOrEmpty(responseBody) ? "无响应" : responseBody)}"));
            }
            var json = System.Text.Json.JsonDocument.Parse(responseBody);
            json.RootElement.TryGetProperty("taskId", out var nonceElement);
            string? taskId = nonceElement.GetString();
            ShowMsg("Captcha_Cloudflare 获取taskId成功,等待解密: " + taskId, 1);
            if (string.IsNullOrEmpty(taskId))
            {
                throw new Exception("Bypass Cloudflare_Turnstile error:" + responseBody);
            }

            string getTask_responseBody=string.Empty;
            for (int i = 0; i < 30; i++)
            {
                request = new(HttpMethod.Post, CaptchaURL+"/getTaskResult");
                var getTask_payload = new
                {
                    clientKey = CaptchaKey,
                    taskId
                };
                var getTask_payloadJson = JsonConvert.SerializeObject(getTask_payload);
                request.Content = new StringContent(getTask_payloadJson);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                HttpResponseMessage getTask_response = await client.SendAsync(request);
                getTask_responseBody = await getTask_response.Content.ReadAsStringAsync();
                try
                {
                    getTask_response.EnsureSuccessStatusCode();
                }
                catch (HttpRequestException ex)
                {
                    throw (new Exception($"{ex.Message}\n响应内容: {(string.IsNullOrEmpty(getTask_responseBody) ? "无响应" : getTask_responseBody)}"));
                }
                var getTask_json = System.Text.Json.JsonDocument.Parse(getTask_responseBody);
                if (getTask_json.RootElement.TryGetProperty("errorId", out var getTask_errorIdElement) &&
                    getTask_json.RootElement.TryGetProperty("solution", out var getTask_solutionElement))
                {
                    int errorId = getTask_errorIdElement.GetInt32();
                    if (errorId == 0 && getTask_solutionElement.ValueKind == System.Text.Json.JsonValueKind.Object)
                    {
                        if (getTask_solutionElement.TryGetProperty("token", out var tokenElement))
                        {
                            string? token = tokenElement.GetString();
                            if (!string.IsNullOrEmpty(token))
                            {
                                return token;
                            }
                        }
                    }
                }
                await Task.Delay(3000);
            }
            throw new Exception("Bypass Cloudflare_Turnstile timeout:" + getTask_responseBody);

        }
        public static async Task<string> Init(AccountInfo accountInfo, string token)
        {
            HttpClientHandler httpClientHandler = new();
            if (accountInfo.Proxy is not null)
            {
                httpClientHandler = new HttpClientHandler
                {
                    Proxy = accountInfo.Proxy,
                    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                };
            }
            HttpClient client = new(httpClientHandler);
            HttpRequestMessage request = new(HttpMethod.Post, "https://auth.privy.io/api/v1/siwe/init");
            request.Headers.Add("accept", "application/json");
            request.Headers.Add("accept-language", "zh-CN,zh;q=0.9,zh-TW;q=0.8,ja;q=0.7,en;q=0.6");
            request.Headers.Add("origin", "https://app.wardenprotocol.org");
            request.Headers.Add("priority", "u=1, i");
            request.Headers.Add("privy-app-id", "cm7f00k5c02tibel0m4o9tdy1");
            request.Headers.Add("privy-ca-id", Guid.NewGuid().ToString());
            request.Headers.Add("privy-client", "react-auth:2.13.8");
            request.Headers.Add("referer", "https://app.wardenprotocol.org/");
            request.Headers.Add("sec-ch-ua", "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"");
            request.Headers.Add("sec-ch-ua-mobile", "?0");
            request.Headers.Add("sec-ch-ua-platform", "\"mcaOS\"");
            request.Headers.Add("sec-fetch-dest", "empty");
            request.Headers.Add("sec-fetch-mode", "cors");
            request.Headers.Add("sec-fetch-site", "cross-site");
            request.Headers.Add("sec-fetch-storage-access", "active");
            request.Headers.Add("user-agent", accountInfo.UserAgent);
            var payload = new
            {
                address = accountInfo.Address,
                token
            };
            var payloadJson = JsonConvert.SerializeObject(payload);
            request.Content = new StringContent(payloadJson);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            HttpResponseMessage response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();
            // 解析JSON获取nonce
            var json = System.Text.Json.JsonDocument.Parse(responseBody);
            json.RootElement.TryGetProperty("nonce", out var nonceElement);
            string? ret = nonceElement.GetString();
            if (!string.IsNullOrEmpty(ret))
            {
                return ret;
            }
            throw new Exception("获取nonce失败");
        }
        public static async Task<string> Authenticate(AccountInfo accountInfo, string nonce)
        {
            HttpClientHandler httpClientHandler = new();
            if (accountInfo.Proxy is not null)
            {
                httpClientHandler = new HttpClientHandler
                {
                    Proxy = accountInfo.Proxy
                };
            }
            HttpClient client = new(httpClientHandler);
            HttpRequestMessage request = new(HttpMethod.Post, "https://auth.privy.io/api/v1/siwe/authenticate");
            request.Headers.Add("accept", "application/json");
            request.Headers.Add("accept-language", "zh-CN,zh;q=0.9,zh-TW;q=0.8,ja;q=0.7,en;q=0.6");
            request.Headers.Add("origin", "https://app.wardenprotocol.org");
            request.Headers.Add("priority", "u=1, i");
            request.Headers.Add("privy-app-id", "cm7f00k5c02tibel0m4o9tdy1");
            request.Headers.Add("privy-ca-id", Guid.NewGuid().ToString());
            request.Headers.Add("privy-client", "react-auth:2.13.8");
            request.Headers.Add("referer", "https://app.wardenprotocol.org/");
            request.Headers.Add("sec-ch-ua", "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"");
            request.Headers.Add("sec-ch-ua-mobile", "?0");
            request.Headers.Add("sec-ch-ua-platform", "\"Windows\"");
            request.Headers.Add("sec-fetch-dest", "empty");
            request.Headers.Add("sec-fetch-mode", "cors");
            request.Headers.Add("sec-fetch-site", "cross-site");
            request.Headers.Add("sec-fetch-storage-access", "active");
            request.Headers.Add("user-agent", accountInfo.UserAgent);

            string message = $"app.wardenprotocol.org wants you to sign in with your Ethereum account:\n{accountInfo.Address}\n\nBy signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\nURI: https://app.wardenprotocol.org\nVersion: 1\nChain ID: 8453\nNonce: {nonce}\nIssued At: {DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss.fffZ}\nResources:\n- https://privy.io";
            var signer = new EthereumMessageSigner();
            string signature = signer.EncodeUTF8AndSign(message, accountInfo.PrivateKey);
            var payload = new
            {
                message,
                signature,
                chainId = "eip155:8453",
                walletClientType = "okx_wallet",
                connectorType = "injected",
                mode = "login-or-sign-up"
            };
            var payloadJson = JsonConvert.SerializeObject(payload);
            request.Content = new StringContent(payloadJson);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            HttpResponseMessage response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();
            var json = System.Text.Json.JsonDocument.Parse(responseBody);
            json.RootElement.TryGetProperty("token", out var nonceElement);
            string? ret = nonceElement.GetString();
            if (!string.IsNullOrEmpty(ret))
            {
                return ret;
            }
            throw new Exception("获取token失败");
        }
        public static async Task<string> SetRferralCode(AccountInfo accountInfo, string token, string referralCode)
        {
            HttpClientHandler httpClientHandler = new();
            if (accountInfo.Proxy is not null)
            {
                httpClientHandler = new HttpClientHandler
                {
                    Proxy = accountInfo.Proxy
                };
            }
            HttpClient client = new(httpClientHandler);
            HttpRequestMessage request = new(HttpMethod.Get, "https://api.app.wardenprotocol.org/api/users/me?referralCode=" + referralCode);
            request.Headers.Add("accept", "*/*");
            request.Headers.Add("accept-language", "zh-CN,zh;q=0.9");
            request.Headers.Add("authorization", "Bearer " + token);
            request.Headers.Add("if-none-match", "W/\"16f-GJ6BhrbtIBLeDXFx7qvvPnPBaWY\"");
            request.Headers.Add("origin", "https://app.wardenprotocol.org");
            request.Headers.Add("priority", "u=1, i");
            request.Headers.Add("referer", "https://app.wardenprotocol.org/");
            request.Headers.Add("sec-ch-ua", "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"");
            request.Headers.Add("sec-ch-ua-mobile", "?0");
            request.Headers.Add("sec-ch-ua-platform", "\"Windows\"");
            request.Headers.Add("sec-fetch-dest", "empty");
            request.Headers.Add("sec-fetch-mode", "cors");
            request.Headers.Add("sec-fetch-site", "same-site");
            request.Headers.Add("user-agent", accountInfo.UserAgent);
            request.Content = new StringContent("");
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            HttpResponseMessage response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();
            var json = System.Text.Json.JsonDocument.Parse(responseBody);
            json.RootElement.TryGetProperty("id", out var nonceElement);
            string? ret = nonceElement.GetString();
            if (!string.IsNullOrEmpty(ret))
            {
                return ret;
            }
            throw new Exception("SetRferralCode失败，无法获取ID");
        }
        public static async Task<string> CreateToken(AccountInfo accountInfo, string token, string userId)
        {
            HttpClientHandler httpClientHandler = new();
            if (accountInfo.Proxy is not null)
            {
                httpClientHandler = new HttpClientHandler
                {
                    Proxy = accountInfo.Proxy
                };
            }
            HttpClient client = new(httpClientHandler);
            HttpRequestMessage request = new(HttpMethod.Post, "https://api.app.wardenprotocol.org/api/tokens");
            request.Headers.Add("accept", "*/*");
            request.Headers.Add("accept-language", "zh-CN,zh;q=0.9");
            request.Headers.Add("authorization", "Bearer " + token);
            request.Headers.Add("origin", "https://app.wardenprotocol.org");
            request.Headers.Add("priority", "u=1, i");
            request.Headers.Add("referer", "https://app.wardenprotocol.org/");
            request.Headers.Add("sec-ch-ua", "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"");
            request.Headers.Add("sec-ch-ua-mobile", "?0");
            request.Headers.Add("sec-ch-ua-platform", "\"Windows\"");
            request.Headers.Add("sec-fetch-dest", "empty");
            request.Headers.Add("sec-fetch-mode", "cors");
            request.Headers.Add("sec-fetch-site", "same-site");
            request.Headers.Add("user-agent", accountInfo.UserAgent);
            // 生成6位随机英文+数字字符串
            string randomTokenName = Guid.NewGuid().ToString("N")[..6].ToUpper();
            request.Content = new StringContent("{\"userId\":\"" + userId + "\",\"tokenName\":\"" + randomTokenName + "\"}");
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            HttpResponseMessage response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();
            var json = System.Text.Json.JsonDocument.Parse(responseBody);
            json.RootElement.TryGetProperty("tokenName", out var nonceElement);
            string? ret = nonceElement.GetString();
            if (!string.IsNullOrEmpty(ret))
            {
                return ret;
            }
            throw new Exception("CreateToken失败");
        }
        public static async Task<string> Daily_Login(AccountInfo accountInfo, string token)
        {
            HttpClientHandler httpClientHandler = new();
            if (accountInfo.Proxy is not null)
            {
                httpClientHandler = new HttpClientHandler
                {
                    Proxy = accountInfo.Proxy
                };
            }
            HttpClient client = new(httpClientHandler);
            HttpRequestMessage request = new(HttpMethod.Post, "https://api.app.wardenprotocol.org/api/tokens/activity");
            request.Headers.Add("accept", "*/*");
            request.Headers.Add("accept-language", "zh-CN,zh;q=0.9,zh-TW;q=0.8,ja;q=0.7,en;q=0.6");
            request.Headers.Add("authorization", "Bearer " + token);
            request.Headers.Add("origin", "https://app.wardenprotocol.org");
            request.Headers.Add("priority", "u=1, i");
            request.Headers.Add("referer", "https://app.wardenprotocol.org/");
            request.Headers.Add("sec-ch-ua", "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"");
            request.Headers.Add("sec-ch-ua-mobile", "?0");
            request.Headers.Add("sec-ch-ua-platform", "\"Windows\"");
            request.Headers.Add("sec-fetch-dest", "empty");
            request.Headers.Add("sec-fetch-mode", "cors");
            request.Headers.Add("sec-fetch-site", "same-site");
            request.Headers.Add("user-agent", accountInfo.UserAgent);
            var payload = new
            {
                activityType = "LOGIN",
                metadata = new
                {
                    action = "user_login",
                    timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    source = "privy",
                }
            };
            var payloadJson = JsonConvert.SerializeObject(payload);
            request.Content = new StringContent(payloadJson);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            HttpResponseMessage response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();
            if (!string.IsNullOrEmpty(responseBody))
            {
                return responseBody;
            }
            throw new Exception("Daily_Login失败");
        }
        public static async Task<string> Daily_Chat(AccountInfo accountInfo, string token)
        {
            HttpClientHandler httpClientHandler = new();
            if (accountInfo.Proxy is not null)
            {
                httpClientHandler = new HttpClientHandler
                {
                    Proxy = accountInfo.Proxy
                };
            }
            HttpClient client = new(httpClientHandler);
            HttpRequestMessage request = new(HttpMethod.Post, "https://api.app.wardenprotocol.org/api/tokens/activity");
            request.Headers.Add("accept", "*/*");
            request.Headers.Add("accept-language", "zh-CN,zh;q=0.9,zh-TW;q=0.8,ja;q=0.7,en;q=0.6");
            request.Headers.Add("authorization", "Bearer " + token);
            request.Headers.Add("origin", "https://app.wardenprotocol.org");
            request.Headers.Add("priority", "u=1, i");
            request.Headers.Add("referer", "https://app.wardenprotocol.org/");
            request.Headers.Add("sec-ch-ua", "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"");
            request.Headers.Add("sec-ch-ua-mobile", "?0");
            request.Headers.Add("sec-ch-ua-platform", "\"Windows\"");
            request.Headers.Add("sec-fetch-dest", "empty");
            request.Headers.Add("sec-fetch-mode", "cors");
            request.Headers.Add("sec-fetch-site", "same-site");
            request.Headers.Add("user-agent", accountInfo.UserAgent);
            var payload = new
            {
                activityType = "CHAT_INTERACTION",
                metadata = new
                {
                    action = "user_chat",
                    message_length = 10,
                    timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
            };
            var payloadJson = JsonConvert.SerializeObject(payload);
            request.Content = new StringContent(payloadJson);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            HttpResponseMessage response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();
            if (!string.IsNullOrEmpty(responseBody))
            {
                return responseBody;
            }
            throw new Exception("Daily_Chat失败");
        }
        public static async Task<string> Daily_Game(AccountInfo accountInfo, string token)
        {
            HttpClientHandler httpClientHandler = new();
            if (accountInfo.Proxy is not null)
            {
                httpClientHandler = new HttpClientHandler
                {
                    Proxy = accountInfo.Proxy
                };
            }
            HttpClient client = new(httpClientHandler);
            HttpRequestMessage request = new(HttpMethod.Post, "https://api.app.wardenprotocol.org/api/tokens/activity");
            request.Headers.Add("accept", "*/*");
            request.Headers.Add("accept-language", "zh-CN,zh;q=0.9");
            request.Headers.Add("authorization", "Bearer " + token);
            request.Headers.Add("origin", "https://app.wardenprotocol.org");
            request.Headers.Add("priority", "u=1, i");
            request.Headers.Add("referer", "https://app.wardenprotocol.org/");
            request.Headers.Add("sec-ch-ua", "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"");
            request.Headers.Add("sec-ch-ua-mobile", "?0");
            request.Headers.Add("sec-ch-ua-platform", "\"Windows\"");
            request.Headers.Add("sec-fetch-dest", "empty");
            request.Headers.Add("sec-fetch-mode", "cors");
            request.Headers.Add("sec-fetch-site", "same-site");
            request.Headers.Add("user-agent", accountInfo.UserAgent);
            var payload = new
            {
                activityType = "GAME_PLAY",
                metadata = new
                {
                    action = "user_game",
                    timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
            };
            var payloadJson = JsonConvert.SerializeObject(payload);
            request.Content = new StringContent(payloadJson);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            HttpResponseMessage response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();
            if (!string.IsNullOrEmpty(responseBody))
            {
                return responseBody;
            }
            throw new Exception("Daily_Game失败");
        }
        public static async Task<string> Daily_Swap(AccountInfo accountInfo, string token)
        {
            HttpClientHandler httpClientHandler = new();
            if (accountInfo.Proxy is not null)
            {
                httpClientHandler = new HttpClientHandler
                {
                    Proxy = accountInfo.Proxy
                };
            }
            HttpClient client = new(httpClientHandler);
            HttpRequestMessage request = new(HttpMethod.Post, "https://api.app.wardenprotocol.org/api/tokens/activity");
            request.Headers.Add("accept", "*/*");
            request.Headers.Add("accept-language", "zh-CN,zh;q=0.9");
            request.Headers.Add("authorization", "Bearer " + token);
            request.Headers.Add("origin", "https://app.wardenprotocol.org");
            request.Headers.Add("priority", "u=1, i");
            request.Headers.Add("referer", "https://app.wardenprotocol.org/");
            request.Headers.Add("sec-ch-ua", "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"");
            request.Headers.Add("sec-ch-ua-mobile", "?0");
            request.Headers.Add("sec-ch-ua-platform", "\"Windows\"");
            request.Headers.Add("sec-fetch-dest", "empty");
            request.Headers.Add("sec-fetch-mode", "cors");
            request.Headers.Add("sec-fetch-site", "same-site");
            request.Headers.Add("user-agent", accountInfo.UserAgent);
            var payload = new
            {
                activityType = "WALLET_TRANSACTION",
                metadata = new
                {
                    action = "swap_request",
                    message = "It seems that the swap request is being rate-limited due to too many requests being sent in a short period. \n\nI will attempt the swap again. Please hold on for a moment.",
                    timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
            };
            var payloadJson = JsonConvert.SerializeObject(payload);
            request.Content = new StringContent(payloadJson);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            HttpResponseMessage response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();
            if (!string.IsNullOrEmpty(responseBody))
            {
                return responseBody;
            }
            throw new Exception("Daily_Swap");
        }
        public static async Task<string> GetTokenInfo(AccountInfo accountInfo, string token)
        {
            HttpClientHandler httpClientHandler = new();
            if (accountInfo.Proxy is not null)
            {
                httpClientHandler = new HttpClientHandler
                {
                    Proxy = accountInfo.Proxy
                };
            }
            HttpClient client = new(httpClientHandler);
            HttpRequestMessage request = new(HttpMethod.Get, "https://api.app.wardenprotocol.org/api/tokens/user/me");

            request.Headers.Add("accept", "*/*");
            request.Headers.Add("accept-language", "zh-CN,zh;q=0.9,zh-TW;q=0.8,ja;q=0.7,en;q=0.6");
            request.Headers.Add("authorization", "Bearer " + token);
            request.Headers.Add("if-none-match", "W/\"12e-3rINz4PHUkw+aLl/RtjYOqYuA+k\"");
            request.Headers.Add("origin", "https://app.wardenprotocol.org");
            request.Headers.Add("priority", "u=1, i");
            request.Headers.Add("referer", "https://app.wardenprotocol.org/");
            request.Headers.Add("sec-ch-ua", "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"");
            request.Headers.Add("sec-ch-ua-mobile", "?0");
            request.Headers.Add("sec-ch-ua-platform", "\"Windows\"");
            request.Headers.Add("sec-fetch-dest", "empty");
            request.Headers.Add("sec-fetch-mode", "cors");
            request.Headers.Add("sec-fetch-site", "same-site");
            request.Headers.Add("user-agent", accountInfo.UserAgent);
            request.Content = new StringContent("");
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            HttpResponseMessage response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();
            var json = System.Text.Json.JsonDocument.Parse(responseBody);
            if (json.RootElement.TryGetProperty("token", out var tokenElement) &&
                tokenElement.TryGetProperty("pointsTotal", out var pointsElement))
            {
                double points = pointsElement.GetDouble();
                return points.ToString();
            }
            throw new Exception("GetToken_Info失败");
        }
        public static async Task Script(AccountInfo accountInfo)
        {
            ShowMsg($"当前时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}", 0);
            ShowMsg("当前执行账号:" + accountInfo.Index + " - " + accountInfo.Address, 0);
            string cf_token = await Captcha_Cloudflare();
            string nonce = await Init(accountInfo, cf_token);
            ShowMsg("获取nonce成功", 1);
            string token = await Authenticate(accountInfo, nonce);
            ShowMsg("获取token成功", 1);
            ////如果需要设置推荐码和拉新，可以取消下面的注释
            //string RferralCodeList = "R785A,66DN8,IDG6J,4SX9I,ZIKGX,NCZGY,99W7A,XYA16,HNBLY,IIBR7,62LRE,A4H3F,HZKL3,VF6KQ,AOPBA,K4583,V5Z9S,TF8JM,HDXC8,S85PX,0RESR,CAVZY,4V3YC,KRAXY";
            //string[] codeArray = RferralCodeList.Split(',');
            //string RferralCode = codeArray[new Random().Next(codeArray.Length)];
            //string userId = await SetRferralCode(accountInfo, token, RferralCode);
            //ShowMsg("设置推荐码成功:返回userId " + userId, 1);
            //string createTokenResponse = await CreateToken(accountInfo, token, userId);
            //ShowMsg("创建Token成功: " + createTokenResponse, 1);
            string dailyLoginResponse = await Daily_Login(accountInfo, token);
            ShowMsg("每日登录成功: " + dailyLoginResponse, 1);
            string dailyChatResponse = await Daily_Chat(accountInfo, token);
            ShowMsg("每日聊天成功: " + dailyChatResponse, 1);
            string dailyGameResponse = await Daily_Game(accountInfo, token);
            ShowMsg("每日游戏成功: " + dailyGameResponse, 1);
            string dailySwapResponse = await Daily_Swap(accountInfo, token);
            ShowMsg("每日Swap成功: " + dailySwapResponse, 1);
            string tokenInfo = await GetTokenInfo(accountInfo, token);
            ShowMsg("Token积分: " + tokenInfo, 1);
            RecordPoints(accountInfo.Index, DateTime.Now.ToString("yyyy-MM-dd"), tokenInfo);
        }
        public static void LoadPrivateKeyAndProxyAndLog()
        {
            if (!File.Exists("PrivateKey.txt"))
                File.Create("PrivateKey.txt").Close();
            if (!File.Exists("Proxy.txt"))
                File.Create("Proxy.txt").Close();
            if (!File.Exists("CaptchaKey.txt"))
                File.Create("CaptchaKey.txt").Close();
            if (!File.Exists("Log.csv"))
                File.Create("Log.csv").Close();
            string[] privateKey = File.ReadAllLines("PrivateKey.txt");
            string[] proxy = File.ReadAllLines("Proxy.txt");
            string[] csvData = File.ReadAllLines("Log.csv");
            CaptchaKey = File.ReadAllText("CaptchaKey.txt").Trim();
            if(CaptchaKey.Length == 0)
            {
                ShowMsg("未配置打码平台密钥，请查看使用说明！", 3);
                Thread.Sleep(3000);
                Environment.Exit(0);
            }
            if (privateKey.Length == 0)
            {
                ShowMsg("未写私钥信息，程序即将退出！！！", 3);
                Thread.Sleep(3000);
                Environment.Exit(0);
            }
            AccountInfoList.Clear();
            int index = 1;
            foreach (var line in privateKey)
            {
                string key = line.Trim();
                if (string.IsNullOrWhiteSpace(key))
                {
                    continue;
                }
                try
                {
                    var ethKey = new EthECKey(key);
                    var address = ethKey.GetPublicAddress();
                    AccountInfoList.Add(new AccountInfo
                    {
                        Index = index,
                        Address = address,
                        PrivateKey = ethKey
                    });
                    // 初始化DataMatrix，如果csvData没有数据或csv数据长度不等于privateKey，把每个账号初始化为空(占位)
                    // 如果csvData有数据且长度等于privateKey，则从csvData中读取数据进行初始化
                    if (csvData.Length > 1 && csvData.Length - 1 == privateKey.Length)
                    {
                        // csv第一行为表头，后续每行为账号数据
                        var header = csvData[0].Split(',');
                        var row = csvData[index]; // index从1开始，正好对应csv的第index行
                        var cells = row.Split(',');
                        var dict = new Dictionary<string, string>();
                        for (int i = 1; i < header.Length && i < cells.Length; i++)
                        {
                            if (!string.IsNullOrWhiteSpace(header[i]) && !string.IsNullOrWhiteSpace(cells[i]))
                                dict[header[i]] = cells[i];
                        }
                        DataMatrix[index] = dict;
                    }
                    else
                    {
                        DataMatrix[index] = [];
                    }
                    index++;
                }
                catch (Exception ex)
                {
                    ShowMsg($"私钥无效: {key} ({ex.Message})", 3);
                }
            }
            if (AccountInfoList.Count == 0)
            {
                ShowMsg("没有有效的私钥，程序即将退出！", 3);
                Thread.Sleep(3000);
                Environment.Exit(0);
            }
            ShowMsg($"已加载 {AccountInfoList.Count} 条私钥", 1);
            // 向AccountInfoList中添加代理信息，注意Proxy.txt的格式为: IP:Port:Username:Password
            // 如果代理数量不足，则只为前N个账户分配代理，其余账户Proxy为null
            int proxyLine = proxy.Length;
            for (int i = 0; i < AccountInfoList.Count && i < proxyLine; i++)
            {
                var line = proxy[i].Trim();
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                try
                {
                    if (line.StartsWith("socks", StringComparison.OrdinalIgnoreCase))
                    {
                        ShowMsg($"不支持 SOCKS 代理，请改用Http或Https代理， {line}", 2);
                        continue;
                    }

                    var uri = new Uri(
                        line.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                        line.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                        ? line : $"http://{line}"
                    );
                    var webProxy = new WebProxy(uri);
                    // 如果Uri中包含用户名和密码，则设置Credentials
                    if (!string.IsNullOrEmpty(uri.UserInfo))
                    {
                        var userInfo = uri.UserInfo.Split(':');
                        if (userInfo.Length == 2)
                        {
                            webProxy.Credentials = new NetworkCredential(userInfo[0], userInfo[1]);
                        }
                    }
                    AccountInfoList[i].Proxy = webProxy;
                }
                catch (Exception ex)
                {
                    ShowMsg($"代理格式错误: {line} ({ex.Message})", 3);
                }
            }
            int proxyCount = AccountInfoList.Count(x => x.Proxy is not null);
            ShowMsg($"已加载 {proxyCount} 条代理", proxyCount > 0 ? 1 : 2);
        }
        public static string GetRandomUserAgent()
        {
            Random random = new();
            int revisionVersion = random.Next(1, 8000);
            int tailVersion = random.Next(1, 150);
            return $"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.{revisionVersion}.{tailVersion} Safari/537.36";
        }
        public static void RecordPoints(int accountIndex, string date, string value)
        {
            lock (_dataLock)
            {
                if (!DataMatrix.TryGetValue(accountIndex, out var dateDict))
                {
                    dateDict = [];
                    DataMatrix[accountIndex] = dateDict;
                }
                dateDict[date] = value;
            }
        }
        public static void ExportDataMatrixToCsv()
        {
            lock (_dataLock)
            {
                // 收集所有日期
                var allDates = DataMatrix.Values
                    .SelectMany(dict => dict.Keys)
                    //.Where(d => !string.IsNullOrWhiteSpace(d))
                    .Distinct()
                    .OrderBy(d => d)
                    .ToList();

                using var writer = new StreamWriter("Log.csv", false, System.Text.Encoding.UTF8);
                // 写表头
                writer.Write("账号索引/日期");
                foreach (var date in allDates)
                {
                    writer.Write($",{date}");
                }
                writer.WriteLine();

                // 写每一行
                foreach (var kvp in DataMatrix.OrderBy(x => x.Key))
                {
                    writer.Write(kvp.Key);
                    foreach (var date in allDates)
                    {
                        if (kvp.Value.TryGetValue(date, out var val))
                            writer.Write($",{val}");
                        else
                            writer.Write(","); // 未记录则留空
                    }
                    writer.WriteLine();
                }

                // 清理最早一天的日期（只保留最近30天）
                if (allDates.Count > 30)
                {
                    var removeDates = allDates.Take(allDates.Count - 30).ToList();
                    foreach (var dict in DataMatrix.Values)
                    {
                        foreach (var date in removeDates)
                        {
                            dict.Remove(date);
                        }
                    }
                }
            }
        }
        public static void ShowMsg(string msg, int logLevel)
        {
            string logFile = $"Log.txt";
            string logText = $"{DateTime.Now} - {msg}\n";
            ConsoleColor color = ConsoleColor.White;
            switch (logLevel)
            {
                case 1:
                    color = ConsoleColor.Green;
                    msg = " ✔   " + msg;
                    break;
                case 2:
                    color = ConsoleColor.DarkYellow;
                    msg = " ⚠   " + msg;
                    break;
                case 3:
                    color = ConsoleColor.Red;
                    msg = " ❌   " + msg;
                    break;
            }
            lock (_lock)
            {
                Console.ForegroundColor = color;
                Console.WriteLine(msg);
                Console.ResetColor();
                File.AppendAllText(logFile, logText);
            }
        }
        public class AccountInfo
        {
            public int Index { get; set; }
            public string Address { get; set; } = string.Empty;
            public WebProxy? Proxy { get; set; }
            public EthECKey? PrivateKey { get; set; }
            public string UserAgent { get; set; } = GetRandomUserAgent();
            public int FailTime { get; set; }
            public DateTime NextExecutionTime { get; set; } = DateTime.MinValue;

        }
    }
}
