using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;

namespace WXAuthWeb.common
{
    ///<summary>
    ///微信帮助类
    ///</summary>
    public class WXHelper
    {
        private static string appId = ConfigurationManager.AppSettings["appid"];
        private static string secret = ConfigurationManager.AppSettings["appsecret"];
        /// <summary>
        /// 发起请求
        /// </summary>
        /// <param name="url">地址</param>
        /// <param name="data">数据</param>
        /// <param name="reqtype">请求类型</param>
        /// <returns></returns>
        public String Request(string url, string data, string reqtype)
        {
            HttpWebRequest web = (HttpWebRequest)HttpWebRequest.Create(url);
            web.ContentType = "application/json";
            web.Method = reqtype;
            if (data.Length > 0 && reqtype.Trim().ToUpper() == "POST")
            {
                byte[] postBytes = Encoding.UTF8.GetBytes(data);
                web.ContentLength = postBytes.Length;
                using (Stream reqStream = web.GetRequestStream())
                {
                    reqStream.Write(postBytes, 0, postBytes.Length);
                }
            }
            string html = string.Empty;
            using (HttpWebResponse response = (HttpWebResponse)web.GetResponse())
            {
                Stream responseStream = response.GetResponseStream();
                StreamReader streamReader = new StreamReader(responseStream, Encoding.UTF8);
                html = streamReader.ReadToEnd();
            }
            return html;
        }
        ///<summary>
        ///生成随机字符串 
        ///</summary>
        ///<param name="length">目标字符串的长度</param>
        ///<param name="useNum">是否包含数字，1=包含，默认为包含</param>
        ///<param name="useLow">是否包含小写字母，1=包含，默认为包含</param>
        ///<param name="useUpp">是否包含大写字母，1=包含，默认为包含</param>
        ///<param name="useSpe">是否包含特殊字符，1=包含，默认为不包含</param>
        ///<param name="custom">要包含的自定义字符，直接输入要包含的字符列表</param>
        ///<returns>指定长度的随机字符串</returns>
        public static string GetRandomString(int length, bool useNum, bool useLow, bool useUpp, bool useSpe, string custom)
        {
            byte[] b = new byte[4];
            new System.Security.Cryptography.RNGCryptoServiceProvider().GetBytes(b);
            Random r = new Random(BitConverter.ToInt32(b, 0));
            string s = null, str = custom;
            if (useNum == true) { str += "0123456789"; }
            if (useLow == true) { str += "abcdefghijklmnopqrstuvwxyz"; }
            if (useUpp == true) { str += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; }
            if (useSpe == true) { str += "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; }
            for (int i = 0; i < length; i++)
            {
                s += str.Substring(r.Next(0, str.Length - 1), 1);
            }
            return s;
        }
        /// <summary>
        /// Base64加密，采用utf8编码方式加密
        /// </summary>
        /// <param name="source">待加密的明文</param>
        /// <returns>加密后的字符串</returns>
        public static string EncodeBase64(string source)
        {
            return EncodeBase64(Encoding.UTF8, source);
        }
        /// <summary>
        /// Base64加密
        /// </summary>
        /// <param name="codeName">加密采用的编码方式</param>
        /// <param name="source">待加密的明文</param>
        /// <returns></returns>
        public static string EncodeBase64(Encoding encode, string source)
        {
            string enString = "";
            byte[] bytes = encode.GetBytes(source);
            try
            {
                enString = Convert.ToBase64String(bytes);
            }
            catch
            {
                enString = source;
            }
            return enString;
        }
        /// <summary>
        /// Base64解密
        /// </summary>
        /// <param name="codeName">解密采用的编码方式，注意和加密时采用的方式一致</param>
        /// <param name="result">待解密的密文</param>
        /// <returns>解密后的字符串</returns>
        public static string DecodeBase64(Encoding encode, string result)
        {
            string decode = "";
            byte[] bytes = Convert.FromBase64String(result);
            try
            {
                decode = encode.GetString(bytes);
            }
            catch
            {
                decode = result;
            }
            return decode;
        }

        /// <summary>
        /// Base64解密，采用utf8编码方式解密
        /// </summary>
        /// <param name="result">待解密的密文</param>
        /// <returns>解密后的字符串</returns>
        public static string DecodeBase64(string result)
        {
            return DecodeBase64(Encoding.UTF8, result);
        }
    }
    ///<summary>
    ///鉴权token 
    ///</summary>
    public class OAuthToken
    {
        ///<summary>
        ///access_token 
        ///</summary>
        public string access_token { get; set; }
        ///<summary>
        ///超时时间 
        ///</summary>
        public int expires_in { get; set; }
        ///<summary>
        ///刷新token 
        ///</summary>
        public string refresh_token { get; set; }
        ///<summary>
        ///用户openid
        ///</summary>
        public string openid { get; set; }
        ///<summary>
        ///授权范围scope 
        ///</summary>
        public string scope { get; set; }

    }
    ///<summary>
    ///AccessToken 
    ///</summary>
    public class AccessToken
    {
        ///<summary>
        ///access_token 
        ///</summary>
        public string access_token { get; set; }
        ///<summary>
        ///超时时间 
        ///</summary>
        public int expires_in { get; set; }
    }
    ///<summary>
    ///用户信息 
    ///</summary>
    public class OAuthUserInfo
    {
        ///<summary>
        ///用户openid
        ///</summary>
        public string openid { get; set; }
        ///<summary>
        ///用户昵称
        ///</summary>
        public string nickname { get; set; }
        ///<summary>
        ///用户性别
        ///</summary>
        public int sex { get; set; }
        ///<summary>
        ///用户省区
        ///</summary>
        public string province { get; set; }
        ///<summary>
        ///用户城市
        ///</summary>
        public string city { get; set; }
        ///<summary>
        ///用户县市
        ///</summary>
        public string country { get; set; }
        ///<summary>
        ///用户头像链接 
        ///</summary>
        public string headimgurl { get; set; }
        ///<summary>
        ///用户权限
        ///</summary>
        public string privilege { get; set; }
        ///<summary>
        ///用户unionid
        ///</summary>
        public string unionid { get; set; }

    }
}