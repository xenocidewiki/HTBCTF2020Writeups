using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp2
{
    class Program
    {
		public static int Iterations = 2;

		// Token: 0x04000002 RID: 2
		public static int KeySize = 256;

		// Token: 0x04000003 RID: 3
		public static byte[] Salt = new byte[]
		{
			21,
			204,
			127,
			153,
			3,
			237,
			10,
			26,
			19,
			103,
			23,
			31,
			55,
			49,
			32,
			57
		};

		public static byte[] Encrypt(byte[] bytes, string password)
		{
			return Encrypt<RijndaelManaged>(bytes, password);
		}

		// Token: 0x06000009 RID: 9 RVA: 0x000024C0 File Offset: 0x000006C0
		public static byte[] Encrypt<T>(byte[] bytes, string password) where T : SymmetricAlgorithm, new()
		{
			byte[] result;
			using (T t = Activator.CreateInstance<T>())
			{
				Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), Salt, Iterations);
				byte[] bytes2 = rfc2898DeriveBytes.GetBytes(KeySize / 8);
				t.Mode = CipherMode.CBC;
				using (ICryptoTransform cryptoTransform = t.CreateDecryptor(bytes2, rfc2898DeriveBytes.GetBytes(16)))
				{
					using (MemoryStream memoryStream = new MemoryStream())
					{
						using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
						{
							cryptoStream.Write(bytes, 0, bytes.Length);
							cryptoStream.FlushFinalBlock();
							result = memoryStream.ToArray();
						}
					}
				}
				t.Clear();
			}
			return result;
		}

		static void Main(string[] args)
        {
			//string privateKey = "<RSAKeyValue><Modulus>slPibiOAhX3YFL90XlFLbhgnmzpDkgPnJrVK23G4ued1Ymy5nu0AcFz3zIihlpi87mZO3N+V3LZ8xplWwYZVh+dbCuASsqePBpJv/bfr+WKAqG5xMOyNF0C62SdWUr5fdoLixMujwvEZ0oKfIfYn2ez+RbOkn3qG0jyE/b4MUPU=</Modulus><Exponent>AQAB</Exponent><P>0eu29eD8IP3LTEx2W8WHHvduTzTR77ueTvQJ78biFO4Jnu/T7Ik/vjvwXSVG1oDYJG8erBmZTMthFjJng9xj1w==</P><Q>2XjUA1vHvhd5Q4RsR4xO/YAOqBcVK25w/CDb6NGTUU9C54+1EhPZdhUAGGIQRKTI21hJZ4f7Cd73NmIf1LlYEw==</Q><DP>XQy5CwBxgkY9aVKzXDaQkH9pHB7zt+pYX/L4vJpR+KkTBqqUK9MiuDZlc0RkxAxUwsGmvO6T72BvZqFtFRwJ/Q==</DP><DQ>dJa5mz9WO4wcH91bq5QGOROxR95wJAOmoRUAsLXCtAG5TamWmqV3nT2u+mOAczygzi9r0wxswqL9h/NdO09Obw==</DQ><InverseQ>w2SRZrsq4mJ5+2HJKUGjaK3YNen51RoFfrP2p+MRc+T+R0Jjfx0kVNj4yHO8dD5xBT3lB+G4atrnbY/TNwlyjQ==</InverseQ><D>BAyDh5ymvmEtFsuCCOIvpEBIJe4cuqP8C5TyLilW2GG4+JMfY8xdxi9WMP6pLJIrN/56q+knres2yguRPLOgHXwfDKhhExraKN2GX0cIeOSOML5zyklGxld9fRi8ltn5bJqeZi0xiYkPxpIliCWQ11oLdNy9NPOLfflErGuBVcE=</D></RSAKeyValue>";
			string privateKey = "<RSAKeyValue><Modulus>5Ja1+N9HfEsTH7qUcefmDTV6rRYRaoY3eZQyFP1mazR0elBDiQDFZ6mWI9FRrSrQsg2wzTj+DKr6bjt7ixiG0vXQVwaNZfEJXTMMjC7SQVKLVGfpbm0+2fVTdYN0OrJIDzlnlQPw8LBsxUB8Bs3I+7b/h9fNnHaJxlbtIQocliU=</Modulus><Exponent>AQAB</Exponent><P>5KcMfUVAcjXycv8OfX+SjOAQAb/H0OA6rNgGo3RLHo1JRyz2rSatbjjdND3Tsk8lU+DXd+IyStPeNGwrG55t1w==</P><Q>/+21PgxbiCQQJG5uKVkjbszpcKOlL0Am0cd9eHcU52wMydiu2fIJf2XCm8bVr8FpcCJLfJxs3s20rz5AC01EYw==</Q><DP>A7nlLjVus23FobIeXlUx4jHUkPK7IuBElISAtzEx+DF9PDezXWb/9IfgsvU++ezoQtGrMTzybN2/BUOuACk4yQ==</DP><DQ>8kW8xTg9jetVvKctcccIW+NvOUoxHUHFfeEzTc6s40bN9GZDX95YT1mtmHnp369geN5+R0Btb52b5ikvx4MlsQ==</DQ><InverseQ>gNdWGXhW2WdpLmLEqJeUjMVq2l+mJxRwlsiSzaw9q03YDrUnpkKl1eROqFyf3it9WvOKnvqC0TSpdhcBsAgRLw==</InverseQ><D>4cDGLue0Xdh3JprKCESSOvFaGp70zFOJbhUh8QDhqXbAohuq1x9f1iTyFqWfGHp0aaSDu+pRXIlvknZEaPbsDoYKZkNK5Qcv3zhaOqh7l1VPfF2G3tm5ghcZV4x86BnMFakAL9kIYuM1XFxaRnUgStke0zR6ykat/EIU3DVoD3E=</D></RSAKeyValue>";
			byte[] result;
			//byte[] bytes = { 0x9F, 0x96, 0x25, 0x71, 0xC8, 0x0D, 0x66, 0x8C, 0x67, 0x80, 0x31, 0x1E, 0x03, 0x71, 0x7B, 0x80, 0x6A, 0x9E, 0x56, 0xC3, 0xB2, 0xBF, 0xA2, 0x15, 0x63, 0x9C, 0x68, 0xC0, 0x53, 0x46, 0x56, 0xD9, 0x88, 0x96, 0xDD, 0x7F, 0x25, 0x27, 0xA3, 0x3A, 0x1D, 0x9D, 0x1A, 0x7E, 0x9B, 0xE7, 0x2A, 0x3D, 0x69, 0x3A, 0x54, 0xCC, 0x97, 0x59, 0x6F, 0x47, 0x61, 0x30, 0x83, 0x8C, 0x0F, 0x9C, 0x92, 0xE0, 0x14, 0x9F, 0x63, 0x4D, 0x07, 0xDD, 0x11, 0x91, 0xED, 0x06, 0x91, 0xFE, 0xD8, 0x2B, 0xCE, 0x82, 0xCC, 0x91, 0x46, 0x0F, 0x2E, 0x03, 0xCE, 0xE7, 0x4F, 0x3F, 0xFE, 0x3F, 0x8A, 0x62, 0x91, 0x4B, 0x08, 0x77, 0xBF, 0x62, 0x03, 0xCB, 0xD0, 0x40, 0x0E, 0x0A, 0x84, 0xC6, 0xB0, 0xE4, 0xAB, 0xF1, 0x39, 0x03, 0x9A, 0x4A, 0xFD, 0x2F, 0xBA, 0x57, 0xE2, 0x78, 0xF7, 0x49, 0xBA, 0xB5, 0x1E, 0xE7 };
			byte[] bytes = { 0x47, 0xA5, 0x8E, 0x3E, 0x07, 0x30, 0x5D, 0x49, 0x88, 0xF6, 0x8A, 0x9E, 0x1D, 0x4B, 0x03, 0x1B, 0x13, 0x19, 0xC0, 0xA2, 0xB1, 0xD0, 0x83, 0xD2, 0xDC, 0xEE, 0x58, 0xDC, 0x78, 0xFC, 0x2E, 0x81, 0x25, 0x51, 0xA5, 0xBD, 0x3C, 0x2C, 0x22, 0x74, 0x3D, 0xFF, 0x0D, 0xF9, 0xD2, 0x83, 0xB3, 0xFD, 0x00, 0xD9, 0xB9, 0xBD, 0x6F, 0x93, 0x5C, 0xBD, 0x0E, 0x2D, 0x8C, 0x48, 0x7B, 0x37, 0x83, 0x00, 0xBC, 0xBE, 0xAF, 0x10, 0x90, 0x45, 0x13, 0x04, 0x4E, 0x1E, 0x1B, 0xC1, 0x5F, 0x06, 0x1B, 0xBB, 0x6D, 0x51, 0xAC, 0xBF, 0x78, 0x9E, 0x62, 0x3A, 0x80, 0xFF, 0xA4, 0x49, 0x3D, 0xAF, 0x44, 0x20, 0xAC, 0xFC, 0x6B, 0x31, 0x53, 0x3B, 0xDF, 0xEF, 0xCA, 0x19, 0x73, 0xF1, 0xD4, 0x80, 0x9C, 0x32, 0x59, 0x31, 0x96, 0xA4, 0x7E, 0x32, 0x6E, 0x31, 0xD3, 0x4A, 0x22, 0x3C, 0x5C, 0x23, 0x0C, 0x09 };
			byte[] filekurwa = File.ReadAllBytes("C:\\Users\\xenocidewiki\\Desktop\\kochamdupeinput");
			
				using (RSACryptoServiceProvider rsacryptoServiceProvider = new RSACryptoServiceProvider(new CspParameters
			{
				ProviderType = 1
			}))
			{
				try
				{
					rsacryptoServiceProvider.FromXmlString(privateKey);
					result = rsacryptoServiceProvider.Decrypt(bytes, false);
				}
				finally
				{
					rsacryptoServiceProvider.PersistKeyInCsp = false;
				}
			}

			string password = Convert.ToBase64String(result);

			byte[] array2 = Encrypt(filekurwa, password);

			File.WriteAllBytes("C:\\Users\\xenocidewiki\\Desktop\\kochamdupe2", array2);

			Console.WriteLine("aaa");
		}
    }
}
