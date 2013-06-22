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
	#region "MemoryProtectionScope enum"
	
	/// <summary>
	/// Sets the range of encryption and decryption operations.
	/// You must specify the same flag when encrypting and decrypting the memory.
	/// </summary>
	public enum MemoryProtectionScope
	{
		/// <summary>
		/// Encrypt and decrypt memory in the same process. An application running in 
		/// a different process will not be able to decrypt the data.
		/// </summary>
		SameProcess = 0,
		/// <summary>
		/// Encrypt and decrypt memory in different processes. An application running 
		/// in a different process will be able to decrypt the data.
		/// </summary>
		CrossProcess = 1,
		/// <summary>
		/// Use the same logon credentials to encrypt and decrypt memory in different 
		/// processes. An application running in a different process will be able to 
		/// decrypt the data. However, the process must run as the same user that 
		/// encrypted the data and in the same logon session. 
		/// </summary>
		SameLogon = 2 
	}
	
	#endregion

	/// <summary>
	/// Encrypts memory to protect sensitive information.
	/// </summary>
	/// <remarks>
	/// This class is supported in Microsoft® Windows® XP operating system and 
	/// later operating systems.
	/// </remarks>
	public sealed class ProtectedMemory
	{
		#region "Constructors & Private members"

		// Since this class provides only static methods, make the default constructor private to prevent 
		// instances from being created with "new ProtectedMemory()".
		private ProtectedMemory() {}

		/// <summary>
		/// The ProtectedMemory is based on API functions that are present on Windows XP or better.
		/// </summary>
		private static bool _isSupported = (Environment.OSVersion.Platform == PlatformID.Win32NT && Environment.OSVersion.Version.Major >= 5 && Environment.OSVersion.Version.Minor >= 1);

		#endregion

		#region "Public Constants"

		/// <summary>
		/// The protected number of bytes must be a multiple of this value. 
		/// </summary>
		public const int ProtectedMemoryBlockSize = 8;

		#endregion

		#region "Public Methods"

		#region "Protect"

		/// <summary>
		/// This function encrypts memory to prevent others from viewing sensitive 
		/// information in your process. For example, use this function to encrypt 
		/// memory that contains a password. Encrypting the password prevents others 
		/// from viewing it when the process is paged out to the swap file. 
		/// Otherwise, the password is in plaintext and viewable by others.
		/// </summary>
		/// <remarks>
		///  Typically, you use this function to encrypt sensitive information that you
		///  are going to decrypt while your process is running. 
		///  Do not use this function to save data that you want to decrypt later; 
		///  you will not be able to decrypt the data if the computer is rebooted. 
		///  To save encrypted data to a file to decrypt later, use the <see cref="ProtectedData.Protect(string)"/> function.
		///  <p>
		///  Call the <see cref="Unprotect(byte[])"/> function to decrypt memory encrypted 
		///  with the <see cref="Protect(byte[])"/> function. When you have finished using 
		///  the sensitive information, clear it from memory by calling <see cref="Array.Clear"/> function. 
		///  </p>
		/// </remarks>
		/// <param name="userData">bytes to be protected.</param>
		/// <exception cref="PlatformNotSupportedException">This functionality is not available on the current platform.</exception>
		/// <exception cref="ArgumentNullException">The userData parameter is  null.</exception>
		/// <exception cref="CryptographicException">Exception when executing unmanaged code.</exception>
		/// <permission cref="CryptographicPermission">Demand for encryption permission.</permission>
		public static void Protect(byte[] userData)
		{				
			Protect( userData, MemoryProtectionScope.SameProcess );
		}

		/// <summary>
		/// This function encrypts memory to prevent others from viewing sensitive 
		/// information in your process.
		/// </summary>
		/// <remarks>
		///  For example, use this function to encrypt memory that contains a password. 
		///  Encrypting the password prevents others from viewing it when the process is 
		///  paged out to the swap file. Otherwise, the password is in plaintext and viewable by others.
		///  Typically, you use this function to encrypt sensitive information that you
		///  are going to decrypt while your process is running. 
		///  Do not use this function to save data that you want to decrypt later; 
		///  you will not be able to decrypt the data if the computer is rebooted. 
		///  To save encrypted data to a file to decrypt later, use the <see cref="ProtectedData.Protect(string)"/> function.
		///  <p>
		///  Call the <see cref="Unprotect(byte[])"/> function to decrypt memory encrypted 
		///  with the <see cref="Protect(byte[])"/> function. When you have finished using 
		///  the sensitive information, clear it from memory by calling <see cref="Array.Clear"/> function. 
		///  </p>
		/// </remarks>
		/// <param name="userData">bytes to be protected.</param>
		/// <param name="scope">See <see cref="MemoryProtectionScope"/>.</param>
		/// <exception cref="PlatformNotSupportedException">This functionality is not available on the current platform.</exception>
		/// <exception cref="ArgumentNullException">The userData parameter is  null.</exception>
		/// <exception cref="CryptographicException">Exception when executing unmanaged code.</exception>
		/// <permission cref="CryptographicPermission">Demand for encryption permission.</permission>
		public static void Protect(byte[] userData, MemoryProtectionScope scope)
		{
			// Check if this functionality is present in the current platform
			if( !_isSupported )
			{
				throw new PlatformNotSupportedException( Resource.ResourceManager[ Resource.MessageKey.PlatformNotSupportedException ] );
			}

			// Validate input
			if(userData == null)
			{
				throw new ArgumentNullException("userData");
 			}

			// Check if data to encrypt is a multiple of ProtectedMemoryBlockSize.
			if( userData.Length % ProtectedMemoryBlockSize != 0)
			{
				throw new ArgumentOutOfRangeException( "userData", Resource.ResourceManager[ Resource.MessageKey.InvalidMemoryBlockSize ] );
			}

			// Demand Permission
			new CryptographicPermission( CryptographicPermissionFlags.Encrypt ).Demand();
			// Assert UnamanagedCode (replaced by the SuppressUnmanagedCodeSecurity attribute of the Win32Native class
			//new SecurityPermission( SecurityPermissionFlag.UnmanagedCode ).Assert();

			int	result = Win32Native.SystemFunction040( userData, (uint)userData.Length, (uint)scope );

			if(result < 0)
			{
				throw new CryptographicException( Resource.ResourceManager[ Resource.MessageKey.ProtectMemoryException ], new Win32Exception( Win32Native.LsaNtStatusToWinError( result ) ) );
			}
		}
		
		#endregion

		#region "Unprotect"

		/// <summary>
		/// Decrypts memory that was encrypted using the <see cref="Protect(byte[])"/> function.
		/// </summary>
		/// <param name="encryptedData">bytes to unprotect.</param>
		/// <exception cref="PlatformNotSupportedException">This functionality is not available on the current platform.</exception>
		/// <exception cref="ArgumentOutOfRangeException">The userData parameter lenght is not a multiple of <see cref="ProtectedMemoryBlockSize"/>.</exception>
		/// <exception cref="CryptographicException">Exception when executing unmanaged code.</exception>
		/// <permission cref="CryptographicPermission">Demand for decryption permission.</permission>
		public static void Unprotect(byte[] encryptedData)
		{
			Unprotect( encryptedData, MemoryProtectionScope.SameProcess );
		}

		/// <summary>
		/// Decrypts memory that was encrypted using the <see cref="Protect(byte[])"/> function.
		/// </summary>
		/// <param name="encryptedData">bytes to unprotect.</param>
		/// <param name="scope">See <see cref="MemoryProtectionScope"/>.</param>
		/// <exception cref="PlatformNotSupportedException">This functionality is not available on the current platform.</exception>
		/// <exception cref="ArgumentOutOfRangeException">The userData parameter lenght is not a multiple of <see cref="ProtectedMemoryBlockSize"/>.</exception>
		/// <exception cref="CryptographicException">Exception when executing unmanaged code.</exception>
		/// <permission cref="CryptographicPermission">Demand for decryption permission.</permission>
		public static void Unprotect(byte[] encryptedData, MemoryProtectionScope scope)
		{
			// Check if this functionality is present in the current platform
			if( !_isSupported )
			{
				throw new PlatformNotSupportedException( Resource.ResourceManager[ Resource.MessageKey.PlatformNotSupportedException ] );
			}

			// Validate input
			if( encryptedData == null || encryptedData.Length == 0 )
			{
				throw new ArgumentNullException("encryptedData");
			}
			// Check if data to decrypt is a multiple of ProtectedMemoryBlockSize.
			if ( encryptedData.Length % ProtectedMemoryBlockSize != 0)
			{
				throw new ArgumentOutOfRangeException( "encryptedData", Resource.ResourceManager[ Resource.MessageKey.InvalidMemoryBlockSize ] );
			}

			// Demand Permission
			new CryptographicPermission( CryptographicPermissionFlags.Decrypt ).Demand();
			// Assert UnamanagedCode (replaced by the SuppressUnmanagedCodeSecurity attribute of the Win32Native class
			//new SecurityPermission( SecurityPermissionFlag.UnmanagedCode ).Assert();

			int	result = Win32Native.SystemFunction041( encryptedData, (uint)encryptedData.Length, (uint)scope );

			if (result < 0)
			{
				throw new CryptographicException( Resource.ResourceManager[ Resource.MessageKey.UnprotectMemoryException ], new Win32Exception( Win32Native.LsaNtStatusToWinError( result ) ) );
			}
		}
		
		#endregion

		#endregion
	}

}
