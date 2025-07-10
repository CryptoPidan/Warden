using System.Net;
using System.Net.Http.Headers;
using Nethereum.Signer;
using Newtonsoft.Json;

namespace Warden
{
    internal class Program
    {
        public static List<AccountInfo> AccountInfoList = [];
        static async Task Main()
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            LoadPrivateKeyAndProxy();
            while (true)
            {
                foreach (var account in AccountInfoList)
                {
                    if (DateTime.Now >= account.NextExecutionTime)
                    {
                        try
                        {
                            await Script(account);
                            account.NextExecutionTime = DateTime.Now.AddMinutes(720);
                            account.FailTime = 0;
                        }
                        catch (Exception ex)
                        {
                            account.FailTime += 1;
                            account.NextExecutionTime = DateTime.Now.AddSeconds(2^ account.FailTime);
                            ShowMsg($"执行脚本时出错: {ex.Message}", 3);
                        }
                    }
                }
                Thread.Sleep(1000);
            }
        }
        public static async Task<string> Init(AccountInfo accountInfo)
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
            request.Headers.Add("sec-ch-ua-platform", "\"Windows\"");
            request.Headers.Add("sec-fetch-dest", "empty");
            request.Headers.Add("sec-fetch-mode", "cors");
            request.Headers.Add("sec-fetch-site", "cross-site");
            request.Headers.Add("sec-fetch-storage-access", "active");
            request.Headers.Add("user-agent", accountInfo.UserAgent);
            request.Content = new StringContent("{\"address\":\"" + accountInfo.Address + "\"}");
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            HttpResponseMessage response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();
            // 解析JSON获取nonce
            var json = System.Text.Json.JsonDocument.Parse(responseBody);
            json.RootElement.TryGetProperty("nonce", out var nonceElement);
            string? ret = nonceElement.GetString();
            if(!string.IsNullOrEmpty(ret))
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
        public static async Task<string> SetRferralCode(AccountInfo accountInfo,string token,string referralCode)
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
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, "https://api.app.wardenprotocol.org/api/users/me?referralCode="+ referralCode);
            request.Headers.Add("accept", "*/*");
            request.Headers.Add("accept-language", "zh-CN,zh;q=0.9");
            request.Headers.Add("authorization", "Bearer "+ token);
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
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "https://api.app.wardenprotocol.org/api/tokens");
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
            string randomTokenName = Guid.NewGuid().ToString("N")
                .Substring(0, 6)
                .ToUpper(); 
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
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "https://api.app.wardenprotocol.org/api/tokens/activity");
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
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "https://api.app.wardenprotocol.org/api/tokens/activity");
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
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "https://api.app.wardenprotocol.org/api/tokens/activity");
            request.Headers.Add("accept", "*/*");
            request.Headers.Add("accept-language", "zh-CN,zh;q=0.9");
            request.Headers.Add("authorization", "Bearer "+token);
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
        public static async Task Script(AccountInfo accountInfo)
        {
            ShowMsg($"当前时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}", 0);
            ShowMsg("当前执行账号:" + accountInfo.Index + " - "+ accountInfo.Address, 1);
            string nonce = await Init(accountInfo);
            ShowMsg("获取nonce成功: " + nonce, 1);
            string token = await Authenticate(accountInfo, nonce);
            ShowMsg("获取token成功: " + token, 1);
            // 如果需要设置推荐码和拉新，可以取消下面的注释
            //string RferralCodeList = "AAAAA,BBBBB,CCCCC,DDDDD";
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
            Thread.Sleep(5000);
        }
        public static void LoadPrivateKeyAndProxy()
        {
            if (!File.Exists("PrivateKey.txt"))
                File.Create("PrivateKey.txt").Close();
            if (!File.Exists("Proxy.txt"))
                File.Create("Proxy.txt").Close();
            string[] privateKey = File.ReadAllLines("PrivateKey.txt");
            string[] proxy = File.ReadAllLines("Proxy.txt");
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
                        Index = index++,
                        Address = address,
                        PrivateKey = ethKey
                    });
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
        public static readonly object _lock = new();
        public static void ShowMsg(string msg, int logLevel)
        {
            string projectName = Path.GetFileName(Directory.GetCurrentDirectory());
            string logFile = $"{projectName}_Log.txt";
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
