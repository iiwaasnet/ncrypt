using System;
using System.Text;
using Microsoft.Win32;

namespace NCrypto.Security.Cryptography
{
	public enum RegistryHive
	{
		HKLM,
		HKCR,
		HKCU,
		HKU,
		HKCC
	}

	public class RegistryCryptoUtility
	{
		private const string COLON_DELIMITER = ":";
		private const string COMMA_DELIMITER = ",";
		private const string BACKSLASH_DELIMITER = "\\";
		private const string REGISTRY_PREFIX = "registry:";

		/// <summary>
		/// Receives a string in the format:
		/// registry:HKLM\Software\ASP.NET\MyKey\ASPNET_SETREG,keyName
		/// and pulls the value from the correct registry hive, and extracts and
		/// decrypts the configuration information.
		/// </summary>
		/// <param name="pathToConfig"></param>
		/// <returns></returns>
		public static string DecryptRegistryConnectionString(string pathToConfig)
		{
			RegistryKey regKey;
			Byte[] registryBytes;

			if (pathToConfig.StartsWith(REGISTRY_PREFIX))
			{
				var regKeyPathAndKey = pathToConfig.Split(COLON_DELIMITER.ToCharArray())[1];
				var regKeyPath = regKeyPathAndKey.Split(COMMA_DELIMITER.ToCharArray())[0];
				var keyName = regKeyPathAndKey.Split(COMMA_DELIMITER.ToCharArray())[1];
				RegistryKey regkeyHive; // Open the proper Registry Hive

				if (regKeyPath.StartsWith(Enum.GetName(typeof(RegistryHive), RegistryHive.HKLM)))
				{
					regkeyHive = Registry.LocalMachine;
				}
				else if (regKeyPath.StartsWith(Enum.GetName(typeof(RegistryHive), RegistryHive.HKCR)))
				{
					regkeyHive = Registry.ClassesRoot;
				}
				else if (regKeyPath.StartsWith(Enum.GetName(typeof(RegistryHive), RegistryHive.HKCU)))
				{
					regkeyHive = Registry.CurrentUser;
				}
				else if (regKeyPath.StartsWith(Enum.GetName(typeof(RegistryHive), RegistryHive.HKU)))
				{
					regkeyHive = Registry.Users;
				}
				else if (regKeyPath.StartsWith(Enum.GetName(typeof(RegistryHive), RegistryHive.HKCC)))
				{
					regkeyHive = Registry.Users;
				}
				else
				{
					throw new Exception("Unknown Key reference: " + regKeyPath);
				}

				var seperatorPosition = regKeyPath.IndexOf(BACKSLASH_DELIMITER, 0) + 1;
				regKeyPath = regKeyPath.Substring(seperatorPosition, regKeyPath.Length - seperatorPosition);
				regKey = regkeyHive.OpenSubKey(regKeyPath);
				registryBytes = (Byte[]) regKey.GetValue(keyName);
				return Encoding.Unicode.GetString(ProtectedData.Unprotect(registryBytes));
			}
			else
			{
				// return the Config string, registry not specified           
				return pathToConfig;
			}
		}
	}
}