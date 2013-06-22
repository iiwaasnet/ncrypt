/***********************************************************************************
'
' This program is free software; you can redistribute it and/or modify
' it under the terms of the GNU General Public License as published by
' the Free Software Foundation; either version 2 of the License, or
' (at your option) any later version.
'
' This program is distributed in the hope that it will be useful,
' but WITHOUT ANY WARRANTY; without even the implied warranty of
' MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
' GNU General Public License for more details.
'
' Copyright (C) 2004 Hernan de Lahitte (http://weblogs.asp.net/hernandl)
'
'***********************************************************************************/

using System;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Permissions;

namespace NCrypto.Security.Cryptography
{

	#region "DataProtectionScope enum"

	/// <summary>
	/// Scope of data protection.
	/// </summary>
	public enum DataProtectionScope
	{
		/// <summary>
		/// Associates the data encrypted with the current user. The user credentials are used as key material for protecting the data.
		/// </summary>
		CurrentUser = 0x0,

		/// <summary>
		/// Associates the data encrypted with the current computer instead of with an individual user. Any user on the computer on which Protect method is called can use the Unprotect method to decrypt the data.
		/// </summary>
		LocalMachine = 0x5,
	}

	#endregion

	/// <summary>
	/// This class implement access to DPAPI library.
	/// </summary>
	/// <remarks>
	/// Microsoft® Windows® 2000 operating system and later operating systems
	/// provide the Win32® Data Protection API (DPAPI) for encrypting and decrypting data.
	/// DPAPI is particularly useful in that it can eliminate the key management problem
	/// exposed to applications that use cryptography. While encryption ensures the
	///	data is secure, you must take additional steps to ensure the security of the key.
	/// DPAPI uses the password of the user account associated with the code that calls
	/// the DPAPI functions in order to derive the encryption key. As a result, the operating
	/// system (and not the application) manages the key.
	/// The user profile approach affords an additional layer of security because it limits
	/// who can access the secret. Only the user who encrypts the data can decrypt the data.
	/// However, use of the user profile requires additional development effort when DPAPI is
	/// used from an ASP.NET Web application because you need to take explicit steps to load and 
	/// unload a user profile (ASP.NET does not automatically load a user profile.
	/// The machine store approach is easier to develop because it does not require user
	/// profile management. However, unless an additional entropy parameter is used, it
	/// is less secure because any user on the computer can decrypt data.
	/// (Entropy is a random value designed to make deciphering the secret more difficult).
	/// The problem with using an additional entropy parameter is that this must be securely
	/// stored by the application, which presents another key management issue.
	/// </remarks>		
	public sealed class ProtectedData
	{
		#region "Private Variables & Constructors"

		//Since this class provides only static methods, make the default constructor private to prevent 
		//instances from being created with "new ProtectedData()".
		private ProtectedData()
		{
		}

		#endregion

		#region "Public methods"

		#region "Protect"

		/// <summary>
		/// This function performs encryption on the data in a <see cref="String"/> input data.
		/// </summary>
		/// <remarks>
		/// Decryption can only be done on the computer where the data was encrypted if the 
		/// process identity is not the interactive user, otherwise the user with the same logon 
		/// credentials as the encrypter can decrypt the data..
		/// The function also adds a message authentication code (MAC), which is a keyed integrity check, to the encrypted data to guard against data tampering.
		/// </remarks>
		/// <param name="userData">Data to be protected</param>
		/// <returns>Protected data encoded in base 64.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static string Protect(string userData)
		{
			return Protect(userData, (Environment.UserInteractive) ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine);
		}

		/// <summary>
		/// This function performs encryption on the data in a <see cref="String"/> input data.
		/// </summary>
		/// <remarks>
		/// Decryption can only be done on the computer where the data was encrypted if the 
		/// process identity is not the interactive user, otherwise the user with the same logon 
		/// credentials as the encrypter can decrypt the data..
		/// The function also adds a message authentication code (MAC), which is a keyed integrity check, to the encrypted data to guard against data tampering.
		/// </remarks>
		/// <param name="userData">Data to be protected</param>
		/// <param name="scope">See <see cref="DataProtectionScope"/>.</param>
		/// <returns>Protected data encoded in base 64.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <exception cref="CryptographicException">Exception when executing unmanaged code.</exception>
		/// <permission cref="CryptographicPermission">Demand for encryption permission.</permission>
		[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.Execution | SecurityPermissionFlag.ControlPrincipal)]
		public static string Protect(string userData, DataProtectionScope scope)
		{
			if (userData == null)
			{
				throw new ArgumentNullException("userData");
			}

			byte[] plainText = Utility.DefaultEncoding.GetBytes(userData);

			try
			{
				return Convert.ToBase64String(Protect(plainText, null, scope));
			}
			finally
			{
				// Erase the plain text data.
				Array.Clear(plainText, 0, plainText.Length);
			}
		}

		/// <summary>
		/// This function performs encryption on the data in a byte array input data.
		/// </summary>
		/// <remarks>
		/// Decryption can only be done on the computer where the data was encrypted if the 
		/// process identity is not the interactive user, otherwise the user with the same logon 
		/// credentials as the encrypter can decrypt the data..
		/// The function also adds a message authentication code (MAC), which is a keyed integrity check, to the encrypted data to guard against data tampering.
		/// </remarks>
		/// <param name="userData">Data to be protected. This array should be erased after use with <see cref="Array.Clear"/>.</param>
		/// <returns>Protected data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <exception cref="CryptographicException">Exception when executing unmanaged code.</exception>
		/// <permission cref="CryptographicPermission">Demand for encryption permission.</permission>
		public static byte[] Protect(byte[] userData)
		{
			return Protect(userData, null, (Environment.UserInteractive) ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine);
		}

		/// <summary>
		/// This function performs encryption on the data in a byte array input data.
		/// If <see cref="DataProtectionScope.CurrentUser"/> is specified, only a user 
		/// with the same logon credentials as the encrypter can decrypt the data. 
		/// <b>Warning</b>If the logon credentials are lost or forgotten, the data is usually unrecoverable.
		/// If the <see cref="DataProtectionScope.LocalMachine"/> is used, the encryption and decryption must be done on the same computer 
		/// therefore any user on the same computer where the data was encrypted can recover the data.
		/// </summary>
		/// <remarks>
		/// The function creates a session key to perform the encryption.
		/// The session key is rederived when the data is to be decrypted.
		/// The function also adds a message authentication code (MAC), which is a keyed integrity check, to the encrypted data to guard against data tampering.
		/// </remarks>
		/// <param name="userData">Data to be protected. This array should be erased after use with <see cref="Array.Clear"/>.</param>
		/// <param name="scope">See <see cref="DataProtectionScope"/>.</param>
		/// <returns>Protected data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <exception cref="CryptographicException">Exception when executing unmanaged code.</exception>
		/// <permission cref="CryptographicPermission">Demand for encryption permission.</permission>
		public static byte[] Protect(byte[] userData, DataProtectionScope scope)
		{
			return Protect(userData, null, scope);
		}

		/// <summary>
		/// This function performs encryption on the data in a byte array input data.
		/// If <see cref="DataProtectionScope.CurrentUser"/> is specified, only a user 
		/// with the same logon credentials as the encrypter can decrypt the data. 
		/// <b>Warning</b>If the logon credentials are lost or forgotten, the data is usually unrecoverable.
		/// If the <see cref="DataProtectionScope.LocalMachine"/> is used, the encryption and decryption must be done on the same computer 
		/// therefore any user on the same computer where the data was encrypted can recover the data.
		/// </summary>
		/// <remarks>
		/// The function creates a session key to perform the encryption.
		/// The session key is rederived when the data is to be decrypted.
		/// The function also adds a message authentication code (MAC), which is a keyed integrity check, to the encrypted data to guard against data tampering.
		/// </remarks>
		/// <param name="userData">Data to be protected. This array should be erased after use with <see cref="Array.Clear"/>.</param>
		/// <param name="optionalEntropy">Additional material to be added to the symmetric key used for encryption.</param>
		/// <param name="scope">See <see cref="DataProtectionScope"/>.</param>
		/// <returns>Protected data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <exception cref="CryptographicException">Exception when executing unmanaged code.</exception>
		/// <permission cref="CryptographicPermission">Demand for encryption permission.</permission>
		public static byte[] Protect(byte[] userData, byte[] optionalEntropy, DataProtectionScope scope)
		{
			// Verify input
			if (userData == null)
			{
				throw new ArgumentNullException("userData");
			}
			if (!IsValidScope(scope))
			{
				throw new ArgumentException(Resource.ResourceManager[Resource.MessageKey.InvalidDataProtectionScope]);
			}

			// Demand Permission
			new CryptographicPermission(CryptographicPermissionFlags.Encrypt).Demand();
			// Assert UnamanagedCode (replaced by the SuppressUnmanagedCodeSecurity attribute of the Win32Native class

			// Check to see if the entropy is null
			if (optionalEntropy == null)
			{
				// Allocate something
				optionalEntropy = new byte[0];
			}

			Win32Native.CRYPTOAPI_BLOB cipherTextBlob = new Win32Native.CRYPTOAPI_BLOB();

			// This prevents the garbage collector from moving the object and hence 
			// undermines the efficiency of the garbage collector. We 'll release
			// the reference on the finally block. 
			GCHandle userDataHandle = GCHandle.Alloc(userData, GCHandleType.Pinned);
			GCHandle entropyHandle = GCHandle.Alloc(optionalEntropy, GCHandleType.Pinned);

			try
			{
				Win32Native.CRYPTPROTECT_PROMPTSTRUCT prompt = new Win32Native.CRYPTPROTECT_PROMPTSTRUCT(0);

				Win32Native.CRYPTOAPI_BLOB plainTextBlob = new Win32Native.CRYPTOAPI_BLOB();
				plainTextBlob.cbData = (uint) userData.Length;
				plainTextBlob.pbData = userDataHandle.AddrOfPinnedObject();

				Win32Native.CRYPTOAPI_BLOB entropyBlob = new Win32Native.CRYPTOAPI_BLOB();
				entropyBlob.cbData = (uint) optionalEntropy.Length;
				entropyBlob.pbData = entropyHandle.AddrOfPinnedObject();

				if (!Win32Native.CryptProtectData(ref plainTextBlob,
				                                  null,
				                                  ref entropyBlob,
				                                  IntPtr.Zero,
				                                  ref prompt,
				                                  (uint) scope,
				                                  ref cipherTextBlob))
				{
					throw new CryptographicException(Resource.ResourceManager[Resource.MessageKey.ProtectDataException], new Win32Exception(Marshal.GetLastWin32Error()));
				}

				//Check returned data
				if (cipherTextBlob.pbData == IntPtr.Zero)
				{
					throw new OutOfMemoryException(Resource.ResourceManager[Resource.MessageKey.OutOfMemoryException, "cipherTextBlob"]);
				}

				// Move encrypted data to the returned array
				byte[] cipherText = new byte[cipherTextBlob.cbData];
				Marshal.Copy(cipherTextBlob.pbData, cipherText, 0, cipherText.Length);

				return cipherText;
			}
			finally
			{
				// Free the allocated handles
				if (userDataHandle.IsAllocated)
				{
					userDataHandle.Free();
				}
				if (entropyHandle.IsAllocated)
				{
					entropyHandle.Free();
				}
				//Free the unmanaged resource ...
				// Free and erase the cipherTextBlob
				if (cipherTextBlob.pbData != IntPtr.Zero)
				{
					Win32Native.ZeroMemory(cipherTextBlob.pbData, cipherTextBlob.cbData);
					Win32Native.LocalFree(cipherTextBlob.pbData);
				}
			}
		}

		#endregion

		#region "Unprotect"

		/// <summary>
		/// See <see cref="ProtectedData"/>.
		/// </summary>
		/// <param name="encryptedData">Data to unprotect encoded in base 64.</param>
		/// <returns>Plain text data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <exception cref="CryptographicException">Exception when executing unmanaged code.</exception>
		/// <permission cref="CryptographicPermission">Demand for decryption permission.</permission>
		public static string Unprotect(string encryptedData)
		{
			if (encryptedData == null)
			{
				throw new ArgumentNullException("encryptedData");
			}
			if (!Utility.IsBase64Encoding(encryptedData))
			{
				throw new ArgumentException(Resource.ResourceManager[Resource.MessageKey.Base64EncodingException, encryptedData]);
			}

			return Utility.DefaultEncoding.GetString(Unprotect(Convert.FromBase64String(encryptedData), null, (Environment.UserInteractive) ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine));
		}

		/// <summary>
		/// See <see cref="ProtectedData"/>.
		/// </summary>
		/// <param name="encryptedData">Data to unprotect encoded in base 64.</param>
		/// <param name="scope">See <see cref="DataProtectionScope"/>.</param>
		/// <returns>Plain text data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <exception cref="CryptographicException">Exception when executing unmanaged code.</exception>
		/// <permission cref="CryptographicPermission">Demand for decryption permission.</permission>
		public static string Unprotect(string encryptedData, DataProtectionScope scope)
		{
			if (encryptedData == null)
			{
				throw new ArgumentNullException("encryptedData");
			}
			if (!Utility.IsBase64Encoding(encryptedData))
			{
				throw new ArgumentException(Resource.ResourceManager[Resource.MessageKey.Base64EncodingException, encryptedData]);
			}

			return Utility.DefaultEncoding.GetString(Unprotect(Convert.FromBase64String(encryptedData), null, scope));
		}

		/// <summary>
		/// See <see cref="ProtectedData"/>.
		/// </summary>
		/// <param name="encryptedData">Data to unprotect.</param>
		/// <returns>Plain text data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <exception cref="CryptographicException">Exception when executing unmanaged code.</exception>
		/// <permission cref="CryptographicPermission">Demand for decryption permission.</permission>
		public static byte[] Unprotect(byte[] encryptedData)
		{
			return Unprotect(encryptedData, null, (Environment.UserInteractive) ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine);
		}

		/// <summary>
		/// See <see cref="ProtectedData"/>.
		/// </summary>
		/// <param name="encryptedData">Data to unprotect.</param>
		/// <param name="scope">See <see cref="DataProtectionScope"/>.</param>
		/// <returns>Plain text data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <exception cref="CryptographicException">Exception when executing unmanaged code.</exception>
		/// <permission cref="CryptographicPermission">Demand for decryption permission.</permission>
		public static byte[] Unprotect(byte[] encryptedData, DataProtectionScope scope)
		{
			return Unprotect(encryptedData, null, scope);
		}

		/// <summary>
		/// See <see cref="ProtectedData"/>.
		/// </summary>
		/// <param name="encryptedData">Data to unprotect.</param>
		/// <param name="optionalEntropy">Additional material to be added to the symmetric key used for encryption.</param>
		/// <param name="scope">See <see cref="DataProtectionScope"/>.</param>
		/// <returns>Plain text data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <exception cref="CryptographicException">Exception when executing unmanaged code.</exception>
		/// <permission cref="CryptographicPermission">Demand for decryption permission.</permission>
		public static byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, DataProtectionScope scope)
		{
			// Verify input
			if (encryptedData == null || encryptedData.Length == 0)
			{
				throw new ArgumentNullException("encryptedData");
			}
			if (!IsValidScope(scope))
			{
				throw new ArgumentException(Resource.ResourceManager[Resource.MessageKey.InvalidDataProtectionScope]);
			}

			// Demand Permission
			new CryptographicPermission(CryptographicPermissionFlags.Decrypt).Demand();
			// Assert UnamanagedCode (replaced by the SuppressUnmanagedCodeSecurity attribute of the Win32Native class

			// Initialize vars.
			// Check to see if the entropy is null
			if (optionalEntropy == null)
			{
				// Allocate something
				optionalEntropy = new byte[0];
			}

			Win32Native.CRYPTOAPI_BLOB plainTextBlob = new Win32Native.CRYPTOAPI_BLOB();

			GCHandle encryptedDataHandle = GCHandle.Alloc(encryptedData, GCHandleType.Pinned);
			GCHandle entropyHandle = GCHandle.Alloc(optionalEntropy, GCHandleType.Pinned);

			try
			{
				Win32Native.CRYPTPROTECT_PROMPTSTRUCT prompt = new Win32Native.CRYPTPROTECT_PROMPTSTRUCT(0);

				Win32Native.CRYPTOAPI_BLOB encryptedDataBlob = new Win32Native.CRYPTOAPI_BLOB();
				encryptedDataBlob.cbData = (uint) encryptedData.Length;
				encryptedDataBlob.pbData = encryptedDataHandle.AddrOfPinnedObject();

				Win32Native.CRYPTOAPI_BLOB entropyBlob = new Win32Native.CRYPTOAPI_BLOB();
				entropyBlob.cbData = (uint) optionalEntropy.Length;
				entropyBlob.pbData = entropyHandle.AddrOfPinnedObject();

				if (!Win32Native.CryptUnprotectData(ref encryptedDataBlob,
				                                    null,
				                                    ref entropyBlob,
				                                    IntPtr.Zero,
				                                    ref prompt,
				                                    (uint) scope,
				                                    ref plainTextBlob))
				{
					throw new CryptographicException(Resource.ResourceManager[Resource.MessageKey.UnprotectDataException], new Win32Exception(Marshal.GetLastWin32Error()));
				}

				if (plainTextBlob.pbData == IntPtr.Zero)
				{
					throw new OutOfMemoryException(Resource.ResourceManager[Resource.MessageKey.OutOfMemoryException, "plainTextBlob"]);
				}

				byte[] plainText = new byte[plainTextBlob.cbData];
				Marshal.Copy(plainTextBlob.pbData, plainText, 0, plainText.Length);

				return plainText;
			}
			finally
			{
				// Free handles
				if (encryptedDataHandle.IsAllocated)
				{
					encryptedDataHandle.Free();
				}
				if (entropyHandle.IsAllocated)
				{
					entropyHandle.Free();
				}
				//Free the unmanaged resource ...
				// Free and erase the plainTextBlob
				if (plainTextBlob.pbData != IntPtr.Zero)
				{
					Win32Native.ZeroMemory(plainTextBlob.pbData, plainTextBlob.cbData);
					Win32Native.LocalFree(plainTextBlob.pbData);
				}
			}
		}

		#endregion

		#endregion

		#region "Private methods"

		/// <summary>
		/// Validate the DataProtectionScope enum value.
		/// </summary>
		private static bool IsValidScope(DataProtectionScope scope)
		{
			return (scope == DataProtectionScope.CurrentUser ||
			        scope == DataProtectionScope.LocalMachine);
		}

		#endregion
	}
}