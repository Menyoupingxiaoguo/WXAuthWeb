using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace WXAuthWeb.common
{
    /// <summary>
    /// 加解密帮助类
    /// </summary>
    public class EncryptHelper
    {

        //DES用于加密内容较多的敏感信息
        //AES用于加密内容较少强度较高的信息

        /// <summary>
        /// DES加密方法
        /// </summary>
        /// <param name="value">待加密的字符串</param>
        /// <param name="key">8/16位密钥</param>
        /// <returns></returns>
        public static string DesEncrypt(string value, string key)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            byte[] inputByteArray = Encoding.Default.GetBytes(value);
            des.Key = ASCIIEncoding.ASCII.GetBytes(key);
            des.IV = ASCIIEncoding.ASCII.GetBytes(key);
            //创建其支持存储区为内存的流
            MemoryStream ms = new MemoryStream();
            //将数据流链接到加密转换的流
            CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(inputByteArray, 0, inputByteArray.Length);
            //用缓冲区的当前状态更新基础数据源或储存库，随后清除缓冲区
            cs.FlushFinalBlock();
            byte[] EncryptData = (byte[])ms.ToArray();
            return System.Convert.ToBase64String(EncryptData, 0, EncryptData.Length);
        }
        /// <summary>
        /// DES解密方法
        /// </summary>
        /// <param name="value">需要解密的字符串</param>
        /// <param name="key">密钥</param>
        /// <returns></returns> 
        public static string DesDecrypt(string value, string key)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            //Put  the  input  string  into  the  byte  array 
            byte[] inputByteArray = Convert.FromBase64String(value);
            //建立加密对象的密钥和偏移量
            des.Key = ASCIIEncoding.ASCII.GetBytes(key);
            des.IV = ASCIIEncoding.ASCII.GetBytes(key);
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
            //Flush  the  data  through  the  crypto  stream  into  the  memory  stream 
            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();
            return System.Text.Encoding.Default.GetString(ms.ToArray());
        }
        /// <summary>
        /// Aes加密
        /// </summary>
        /// <param name="value">源字符串</param>
        /// <param name="key">aes密钥，长度必须32位</param>
        /// <returns>加密后的字符串</returns>
        public static string AESEncrypt(string value, string key)
        {
            using (AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider())
            {
                aesProvider.Key = Encoding.UTF8.GetBytes(key);
                aesProvider.Mode = CipherMode.ECB;
                aesProvider.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform cryptoTransform = aesProvider.CreateEncryptor())
                {
                    byte[] inputBuffers = Encoding.UTF8.GetBytes(value);
                    byte[] results = cryptoTransform.TransformFinalBlock(inputBuffers, 0, inputBuffers.Length);
                    aesProvider.Clear();
                    aesProvider.Dispose();
                    return Convert.ToBase64String(results, 0, results.Length);
                }
            }
        }
        /// <summary>
        /// Aes解密
        /// </summary>
        /// <param name="value">源字符串</param>
        /// <param name="key">aes密钥，长度必须32位</param>
        /// <returns>解密后的字符串</returns>
        public static string AESDecrypt(string value, string key)
        {
            using (AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider())
            {
                aesProvider.Key = Encoding.UTF8.GetBytes(key);
                aesProvider.Mode = CipherMode.ECB;
                aesProvider.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform cryptoTransform = aesProvider.CreateDecryptor())
                {
                    byte[] inputBuffers = Convert.FromBase64String(value);
                    byte[] results = cryptoTransform.TransformFinalBlock(inputBuffers, 0, inputBuffers.Length);
                    aesProvider.Clear();
                    return Encoding.UTF8.GetString(results);
                }
            }
        }

        /// <summary>
        /// MD5加密
        /// </summary>
        /// <param name="value">需要加密字符串</param>
        /// <returns>返回32位大写字符</returns>
        public static string MD5Encrypt(string value)
        {
            //将输入字符串转换成字节数组  ANSI代码页编码
            var buffer = Encoding.Default.GetBytes(value);
            //接着，创建Md5对象进行散列计算
            var data = MD5.Create().ComputeHash(buffer);
            //创建一个新的Stringbuilder收集字节
            var sb = new StringBuilder();
            //遍历每个字节的散列数据 
            foreach (var t in data)
            {
                //转换大写十六进制字符串
                sb.Append(t.ToString("X2"));
            }
            //返回十六进制字符串
            return sb.ToString();
        }

        /// <summary>  
        /// SHA1加密
        /// </summary>  
        /// <param name="content">需要加密字符串</param>  
        /// <param name="encode">指定加密编码</param>  
        /// <returns>返回40位大写字符串</returns>  
        public static string SHA1(string value)
        {
            //UTF8编码
            var buffer = Encoding.UTF8.GetBytes(value);
            SHA1 sha1 = new SHA1CryptoServiceProvider();
            var data = sha1.ComputeHash(buffer);
            var sb = new StringBuilder();
            foreach (var t in data)
            {
                //转换大写十六进制
                sb.Append(t.ToString("X2"));
            }
            return sb.ToString();
        }


        #region 邹经理旧代码
        /// <summary>
        /// 改造标准密码兼容旧乱码
        /// </summary>
        /// <param name="password"></param>
        /// <returns>[0]MD5 [1]乱码</returns>
        public static string[] NewEncryptPassword(string password)
        {
            string[] passWordArray = new string[] { 
            MD5Encrypt(password),
            EncryptPassword(password)
            };
            return passWordArray;
        }
        /// <summary>
        /// 用户密码加密（*乱码）
        /// </summary>
        /// <param name="password">需要加密字符串</param>
        /// <returns>返回乱码</returns>
        public static string EncryptPassword(string password)
        {
            UnicodeEncoding encoding = new UnicodeEncoding();
            byte[] hashBytes = encoding.GetBytes(password);
            SHA1 sha1 = new SHA1CryptoServiceProvider();
            byte[] cryptPassword = sha1.ComputeHash(hashBytes);
            return SqlTextClear(Encoding.Default.GetString(cryptPassword)); //添加sql字符串过滤
        }
        /// <summary>
        /// SQL注入字符清理
        /// </summary>
        /// <param name="value">需要清理的字符串</param>
        /// <returns></returns>
        public static string SqlTextClear(string value)
        {
            string[] replaceStr = new string[] { ",", "<", ">", "--", "'", "\"", "=", "%", " " };
            foreach (var item in replaceStr)
            {
                value = value.Replace(item, "");
            }
            return value;
        }
        #endregion
    }
}