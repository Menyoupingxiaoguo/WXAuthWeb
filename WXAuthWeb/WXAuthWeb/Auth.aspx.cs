using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using WXAuthWeb.common;

namespace WXAuthWeb
{
    public partial class Auth : System.Web.UI.Page
    {
        public static string appId = ConfigurationManager.AppSettings["appid"];
        public static string secret = ConfigurationManager.AppSettings["appsecret"];
        protected void Page_Load(object sender, EventArgs e)
        {
            if (!IsPostBack)
            {
                string code = Request.QueryString["code"];
                string state = Request.QueryString["state"];

                #region 使用微信AccessToken获取微信用户信息，但不包括用户UnionID信息
                if (!string.IsNullOrEmpty(code))
                {
                    OAuthToken oauthToken = JsonConvert.DeserializeObject<OAuthToken>(new WXHelper().Request(string.Format("https://api.weixin.qq.com/sns/oauth2/access_token?appid={0}&secret={1}&code={2}&grant_type=authorization_code", appId, secret, code), "", "GET"));

                    string accesstoken = string.Empty;
                    AccessToken token = JsonConvert.DeserializeObject<AccessToken>(new WXHelper().Request(string.Format("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={0}&secret={1}", appId, secret), "", "GET"));

                    if (token != null && !string.IsNullOrEmpty(token.access_token))
                    {
                        accesstoken = token.access_token;
                    }

                    if (oauthToken != null && !string.IsNullOrEmpty(oauthToken.openid))
                    {
                        string strResult = new WXHelper().Request(string.Format("https://api.weixin.qq.com/cgi-bin/user/info?access_token={0}&openid={1}&lang=zh_CN", accesstoken, oauthToken.openid), "", "GET");
                        OAuthUserInfo userInfo = JsonConvert.DeserializeObject<OAuthUserInfo>(strResult);

                        if (userInfo != null)
                        {
                            object objUrl = CacheHelper.GetCache(state);
                            if (objUrl != null)
                            {
                                UriBuilder URL = new UriBuilder(objUrl.ToString());
                                string directUrl = URL.ToString();
                                directUrl += string.Format("?openid={0}&nickname={1}&sex={2}&province={3}&city={4}&country={5}&headimgurl={6}&unionid={7}",
                                userInfo.openid, userInfo.nickname, userInfo.sex, userInfo.province, userInfo.city, userInfo.country, userInfo.headimgurl, userInfo.unionid);

                                Response.Redirect(directUrl);
                            }
                        }
                    }
                }
                #endregion

                #region 使用微信SNSToken获取微信用户信息，包括用户UnionID信息
                if (!string.IsNullOrEmpty(code))
                {
                    WXHelper WXHelper = new WXHelper();
                    string strGetSnsToken = WXHelper.Request(string.Format("https://api.weixin.qq.com/sns/oauth2/access_token?appid={0}&secret={1}&code={2}&grant_type=authorization_code", appId, secret, code), "", "GET");
                    JObject jo1 = JsonConvert.DeserializeObject<JObject>(strGetSnsToken);

                    string strResult = WXHelper.Request(string.Format("https://api.weixin.qq.com/sns/userinfo?access_token={0}&openid={1}&lang=zh_CN ", jo1["access_token"].ToString(), jo1["openid"].ToString()), "", "GET");
                    OAuthUserInfo userInfo = JsonConvert.DeserializeObject<OAuthUserInfo>(strResult);
                    if (userInfo != null)
                    {
                        object objUrl = CacheHelper.GetCache(state);
                        if (objUrl != null)
                        {
                            UriBuilder URL = new UriBuilder(objUrl.ToString());
                            string directUrl = URL.ToString();
                            directUrl += string.Format("?openid={0}&nickname={1}&sex={2}&province={3}&city={4}&country={5}&headimgurl={6}&unionid={7}",
                            userInfo.openid, userInfo.nickname, userInfo.sex, userInfo.province, userInfo.city, userInfo.country, userInfo.headimgurl, userInfo.unionid);

                            Response.Redirect(directUrl);
                        }
                    }
                }
                #endregion
            }
        }
    }
}