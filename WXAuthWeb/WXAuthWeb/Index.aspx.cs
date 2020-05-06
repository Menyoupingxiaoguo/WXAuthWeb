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
    public partial class Index : System.Web.UI.Page
    {
        public static string appId = ConfigurationManager.AppSettings["appid"];
        public static string secret = ConfigurationManager.AppSettings["appsecret"];
        protected void Page_Load(object sender, EventArgs e)
        {
            string url = Request.QueryString["url"];
            if (!string.IsNullOrEmpty(url))
            {
                try
                {
                    url = HttpUtility.UrlDecode(url);
                    string state = EncryptHelper.MD5Encrypt(url);
                    //判断url根据MD5生成的密文在缓存中是否存在
                    object objUrl = CacheHelper.GetCache(state);
                    if (objUrl == null)
                    {
                        CacheHelper.AddCache(state, url, 5);//不存在则将url和对应的密文存储在缓存中，存储时长为5分钟
                    }
                    else
                    {
                        CacheHelper.SetCache(state, url, 5);//存在则将url和对应的密文在缓存中更新，更新存储时长为5分钟
                    }
                    Response.Redirect(string.Format("https://open.weixin.qq.com/connect/oauth2/authorize?appid={0}&redirect_uri={1}&response_type=code&scope=snsapi_base&state={2}#wechat_redirect", appId, ConfigurationManager.AppSettings["apppath"] + "/Auth.aspx", state));
                }

                catch (Exception ex)
                {
                    throw ex;
                }

            }
        }
    }
}