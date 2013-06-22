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
using System.Security;
using System.Text;

namespace NCrypto.Security.Cryptography
{
	/// <summary>
	/// Class for handling platform invoke declarations.
	/// </summary>
	/// <remarks><b>IMPORTANT:</b> The use of <see cref="SuppressUnmanagedCodeSecurityAttribute"/> attribute
	/// is subject to an UnmanegedCode permission Demand on the caller class.</remarks>
	[SuppressUnmanagedCodeSecurity]
	internal sealed class Win32Native
	{
		#region "Structs"

		internal struct CRYPTOAPI_BLOB
		{
			public uint cbData;
			public IntPtr pbData;			
		}

		[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Auto)] 
		internal struct CRYPTPROTECT_PROMPTSTRUCT
		{
			public CRYPTPROTECT_PROMPTSTRUCT( int flags )
			{
				this.cbSize = Marshal.SizeOf(typeof(CRYPTPROTECT_PROMPTSTRUCT));
				this.dwPromptFlags = flags;
				this.hwndApp = IntPtr.Zero;
				this.szPrompt = null;
			}

			public int cbSize;
			public int dwPromptFlags;
			public IntPtr hwndApp;
			public String szPrompt;
		}

		public struct CREDUI_INFO 
		{
			public CREDUI_INFO( IntPtr owner, string caption, string message, IntPtr hbmBanner )
			{
				this.cbSize = Marshal.SizeOf(typeof(CREDUI_INFO));
				this.hwndParent = owner; //Specifies the handle to the parent window of the dialog box. If this member is NULL, the desktop will be the parent window of the dialog box.
				this.pszCaptionText = caption.Substring(0, Math.Min(caption.Length, MAX_MSGCAPTION));
				this.pszMessageText = message.Substring(0, Math.Min(message.Length, MAX_MSGCAPTION));
				this.hbmBanner = hbmBanner;
			}

			public int cbSize;
			public IntPtr hwndParent;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pszMessageText;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pszCaptionText;
			public IntPtr hbmBanner;
		}

		#endregion

		#region "DllImport functions"

		#region "ProtectedData"

		[DllImport("crypt32", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
		internal static extern bool CryptProtectData(
			ref CRYPTOAPI_BLOB pDataIn,
			string szDataDescr,
			ref CRYPTOAPI_BLOB pOptionalEntropy, 
			IntPtr pvReserved,
			ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
			uint dwFlags,
			ref CRYPTOAPI_BLOB pDataBlob);

		[DllImport("crypt32", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
		internal static extern bool CryptUnprotectData(
			ref CRYPTOAPI_BLOB pDataIn,
			string szDataDescr,
			ref CRYPTOAPI_BLOB pOptionalEntropy,
			IntPtr pvReserved,
			ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
			uint dwFlags,
			ref CRYPTOAPI_BLOB pDataBlob);

		#endregion

		#region "ProtectedMemory"

		// Declares for Windows XP
		[DllImport("advapi32", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
		internal static extern int SystemFunction040(byte[] pDataIn, uint cbDataIn, uint dwFlags);

		[DllImport("advapi32", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
		internal static extern int SystemFunction041(byte[] pDataIn, uint cbDataIn, uint dwFlags);

        [DllImport("advapi32.dll")]
		internal static extern int LsaNtStatusToWinError(int status);

		#endregion

		#region "aspnet_isapi"

		//TODO: This should not be an absolute path
		[DllImport(@"C:\WINDOWS\Microsoft.NET\Framework\v1.1.4322\aspnet_isapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
		internal static extern int GetGroupsForUser(IntPtr token, StringBuilder allGroups, int allGrpSize, StringBuilder error, int errorSize);
 
		#endregion

		#region "Common functions"

		/// <summary>
		/// The ZeroMemory function fills a block of memory with zeros.
		/// </summary>
		/// <remarks>
		/// For .NET Server use SecureZeroMemory.
		/// For more info see:
		/// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/memory/base/securezeromemory.asp
		/// </remarks>
		[DllImport("kernel32.dll", CharSet=CharSet.Auto)]
		internal static extern void ZeroMemory(IntPtr handle, uint lenght);

		[DllImport("kernel32")]
		internal static extern IntPtr LocalFree(IntPtr handle);

		internal static int Int32Size = Marshal.SizeOf(typeof(int));

		//CloseHandle parameters. When you are finished, 
		//free the memory allocated for the handle.
		[DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
		internal static extern bool CloseHandle(IntPtr handle);

		#endregion

		#region "UICredentials"
		
		// For SecureCredential overload
		[DllImport("credui.dll",SetLastError=true, CharSet=CharSet.Unicode)]
		internal extern static CredUIReturnCodes CredUIPromptForCredentialsW( 
			ref CREDUI_INFO creditUR,
			string targetName,
			IntPtr reserved1,
			int iError,
			StringBuilder userName,
			int maxUserName,
			IntPtr password,
			int maxPassword,
			ref int iSave,
			CredUiFlags flags);

		// For NetworkCredential
		[DllImport("credui.dll", EntryPoint="CredUIPromptForCredentialsW", SetLastError=true, CharSet=CharSet.Unicode)]
		internal extern static CredUIReturnCodes CredUIPromptForCredentialsX( 
			ref CREDUI_INFO creditUR,
			string targetName,
			IntPtr reserved1,
			int iError,
			StringBuilder userName,
			int maxUserName,
			StringBuilder password,
			int maxPassword,
			ref int iSave,
			CredUiFlags flags);

		[DllImport("credui.dll", SetLastError=true, CharSet=CharSet.Unicode)]
		internal extern static CredUIReturnCodes CredUIParseUserNameW(
			string userName,
			StringBuilder user,
			int userMaxChars,
			StringBuilder domain,
			int domainMaxChars);

		[DllImport("credui.dll",SetLastError=true, CharSet=CharSet.Unicode)]
		internal extern static CredUIReturnCodes CredUIConfirmCredentialsW(string targetName, bool confirm);

		[Flags]
		public enum CredUiFlags
		{
			INCORRECT_PASSWORD = 0x1,
			DO_NOT_PERSIST = 0x2,
			REQUEST_ADMINISTRATOR = 0x4,
			EXCLUDE_CERTIFICATES = 0x8,
			REQUIRE_CERTIFICATE = 0x10,
			SHOW_SAVE_CHECK_BOX = 0x40,
			ALWAYS_SHOW_UI = 0x80,
			REQUIRE_SMARTCARD = 0x100,
			PASSWORD_ONLY_OK = 0x200,
			VALIDATE_USERNAME = 0x400,
			COMPLETE_USERNAME = 0x800,
			PERSIST = 0x1000,
			SERVER_CREDENTIAL = 0x4000,
			EXPECT_CONFIRMATION = 0x20000,
			GENERIC_CREDENTIALS = 0x40000,
			USERNAME_TARGET_CREDENTIALS = 0x80000,
			KEEP_USERNAME = 0x100000
		}

		public enum CredUIReturnCodes
		{
			NO_ERROR = 0,
			ERROR_CANCELLED = 1223,
			ERROR_NO_SUCH_LOGON_SESSION = 1312,
			ERROR_NOT_FOUND = 1168,
			ERROR_INVALID_ACCOUNT_NAME = 1315,
			ERROR_INSUFFICIENT_BUFFER = 122,
			ERROR_INVALID_PARAMETER = 87,
			ERROR_INVALID_FLAGS = 1004
		}

		//Maximum number of characters in a string that specifies a user account name.
		public const int MAX_USER_NAME = 100;
		//Maximum number of characters in a string that specifies a password.
		public const int MAX_PASSWORD = 100;
		//Maximum number of characters in a string that specifies a domain name.
		public const int MAX_DOMAIN = 100;
		//Maximum number of characters in a string that specifies a message or caption.
		public const int MAX_MSGCAPTION = 128;

		#endregion

		#region "LogonUser"

		#region Enums
		/// <summary>
		/// Group type enum.
		/// </summary> 
		internal enum SECURITY_IMPERSONATION_LEVEL : int
		{
			SecurityAnonymous = 0,
			SecurityIdentification = 1,
			SecurityImpersonation = 2,
			SecurityDelegation = 3
		}
		internal enum TOKEN_TYPE : int
		{
			TokenPrimary = 1, 
			TokenImpersonation
		}

		#endregion

		internal const int LOGON32_PROVIDER_DEFAULT = 0;

		//		private struct SECURITY_ATTRIBUTES
		//		{
		//			public int nLength;
		//			public IntPtr lpSecurityDescriptor;
		//			public bool bInheritHandle;
		//		}

		//LogonUser parameters
		[DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
		internal static extern bool LogonUser(  string lpszUsername, 
												string lpszDomain, 
												string lpszPassword, 
												int dwLogonType, 
												int dwLogonProvider, 
												ref IntPtr phToken);

		// creates duplicate token handle
		[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
		internal extern static bool DuplicateToken( IntPtr ExistingTokenHandle, 
													int SECURITY_IMPERSONATION_LEVEL, 
													ref IntPtr DuplicateTokenHandle);

		//		[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
		//		internal extern static bool DuplicateTokenEx(IntPtr hToken,
		//													int access, 
		//													ref SECURITY_ATTRIBUTES tokenAttributes,
		//													int impersonationLevel,
		//													int tokenType,
		//													ref IntPtr hNewToken);

		#endregion

		#region "SecureString"

		[DllImport("oleaut32.dll")]
		public static extern int SysStringLen(IntPtr bstr);

		[DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
		public static extern int lstrlenW(IntPtr ptr);

		[DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
		public static extern int lstrlenA(IntPtr ptr);

		[DllImport("oleaut32.dll", CharSet=CharSet.Unicode)]
		public static extern IntPtr SysAllocStringLen(string src, int len);

		#endregion

		#endregion
	}

}
