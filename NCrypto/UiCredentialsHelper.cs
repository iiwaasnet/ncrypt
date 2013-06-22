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
using System.Text;
using System.Net;
using System.Security;
using System.Security.Permissions;

namespace NCrypto.Security.Cryptography
{
	/// <summary>
	/// This class provide access to a feature provided by Windows XP and Windows Server 2003
	/// called "Stored User Names and Passwords" to associate a set of credentials with a single
	/// Windows user account, storing those credentials using the Data Protection API (DPAPI) (See <see cref="ProtectedData"/> class).
	/// This class cannot be inherited.
	/// </summary>
	/// <remarks>
	/// If your application, is running on Windows XP or Windows .NET, 
	/// can use the Credential Management API functions to prompt the user for credentials.
	/// Using these APIs will provide you with a consistent user interface and
	/// will allow you to automatically support the caching of these credentials by the operating system.
	/// </remarks>
	public sealed class UICredentialsHelper
	{
		#region "Priv. vars & contructors"

        /// <summary>
        /// DefaultTargetName.
        /// </summary>
		public static readonly string DefaultTargetName = AppDomain.CurrentDomain.FriendlyName;

		//Since this class provides only static methods, make the default constructor private to prevent 
		//instances from being created with "new UICredentialsHelper()".
		private UICredentialsHelper(){}

		#endregion

		#region "Public methods"

		#region NetworkCredential overloads

		/// <summary>
		/// This method creates and displays a configurable dialog box that accepts credentials information from a user.
		/// </summary>
		/// <remarks>
		/// The default 'targetName' is <see cref="DefaultTargetName"/>
		/// </remarks>
		/// <returns><see cref="NetworkCredential"/> object with the supplied credentials.</returns>
		public static NetworkCredential PromptForCredentials()
		{
			return PromptForCredentials(DefaultTargetName, null, null, IntPtr.Zero);
		}

		/// <summary>
		/// This method creates and displays a configurable dialog box that accepts credentials information from a user.
		/// </summary>
		/// <param name="targetName">Contains the name of the target for the credentials, 
		/// typically a server name. For distributed file system (DFS) connections, 
		/// this string is of the form "servername\sharename".
		/// This parameter is used to identify Target Information when storing and retrieving credentials. 
		/// </param>
		/// <returns><see cref="NetworkCredential"/> object with the supplied credentials.</returns>
		public static NetworkCredential PromptForCredentials(string targetName)
		{
			return PromptForCredentials(targetName, null, null, IntPtr.Zero);
		}

		/// <summary>
		/// This method creates and displays a configurable dialog box that accepts credentials information from a user.
		/// </summary>
		/// <param name="caption">String containing the title for the dialog box.</param>
		/// <param name="message">String containing a brief message to display in the dialog box.</param>
		/// <returns><see cref="NetworkCredential"/> object with the supplied credentials.</returns>
		public static NetworkCredential PromptForCredentials(string caption, string message)
		{
			return PromptForCredentials(DefaultTargetName, caption, message);
		}

		/// <summary>
		/// This method creates and displays a configurable dialog box that accepts credentials information from a user.
		/// </summary>
		/// <param name="targetName">Contains the name of the target for the credentials, 
		/// typically a server name. For distributed file system (DFS) connections, 
		/// this string is of the form "servername\sharename".
		/// This parameter is used to identify Target Information when storing and retrieving credentials. 
		/// </param>
		/// <param name="caption">String containing the title for the dialog box.</param>
		/// <param name="message">String containing a brief message to display in the dialog box.</param>
		/// <returns><see cref="NetworkCredential"/> object with the supplied credentials.</returns>
		public static NetworkCredential PromptForCredentials(string targetName, string caption, string message)
		{
			return PromptForCredentials(targetName, caption, message, IntPtr.Zero);
		}

		/// <summary>
		/// This method creates and displays a configurable dialog box that accepts credentials information from a user.
		/// </summary>
		/// <param name="caption">String containing the title for the dialog box.</param>
		/// <param name="message">String containing a brief message to display in the dialog box.</param>
		/// <param name="owner">Specifies the handle to the parent window of the dialog box.
		/// If this member is NULL, the desktop will be the parent window of the dialog box.
		/// </param>
		/// <returns><see cref="NetworkCredential"/> object with the supplied credentials.</returns>
		public static NetworkCredential PromptForCredentials(string caption, string message, IntPtr owner)
		{
			return PromptForCredentials(DefaultTargetName, caption, message, owner);
		}

		/// <summary>
		/// This method creates and displays a configurable dialog box that accepts credentials information from a user.
		/// </summary>
		/// <param name="targetName">Contains the name of the target for the credentials, 
		/// typically a server name. For distributed file system (DFS) connections, 
		/// this string is of the form "servername\sharename".
		/// This parameter is used to identify Target Information when storing and retrieving credentials. 
		/// </param>
		/// <param name="caption">String containing the title for the dialog box.</param>
		/// <param name="message">String containing a brief message to display in the dialog box.</param>
		/// <param name="owner">Specifies the handle to the parent window of the dialog box.
		/// If this member is NULL, the desktop will be the parent window of the dialog box.
		/// </param>
		/// <returns><see cref="NetworkCredential"/> object with the supplied credentials.</returns>
		/// <permission cref="UIPermission">Demand for <see cref="UIPermissionWindow.SafeTopLevelWindows"/> permission.</permission>
		public static NetworkCredential PromptForCredentials(string targetName, string caption, string message, IntPtr owner)
		{
			// Parameter validation
			if( targetName == null )
			{
				throw new ArgumentNullException( "targetName" );
			}
			if( caption == null )
			{
				caption = String.Empty;
			}
			if( message == null )
			{
				message = String.Empty;
			}			

			new UIPermission( UIPermissionWindow.SafeTopLevelWindows ).Demand();

			// Uncommment this lines to use custom bitmap
			// Bitmap credBMP = new Bitmap(@"..\credui.bmp");
			// replace IntPtr.Zero by credBMP.GetHbitmap()
			Win32Native.CREDUI_INFO creditUI = new Win32Native.CREDUI_INFO(owner, caption, message, IntPtr.Zero);
			int saveCredentials = 0;

			StringBuilder user = new StringBuilder(Win32Native.MAX_USER_NAME);
			StringBuilder pwd = new StringBuilder(Win32Native.MAX_PASSWORD);

			try
			{
				Win32Native.CredUiFlags flags = Win32Native.CredUiFlags.GENERIC_CREDENTIALS |
												Win32Native.CredUiFlags.SHOW_SAVE_CHECK_BOX |
												Win32Native.CredUiFlags.ALWAYS_SHOW_UI |
												Win32Native.CredUiFlags.EXPECT_CONFIRMATION | 
												Win32Native.CredUiFlags.INCORRECT_PASSWORD;

				//For more info see:
				//http://msdn.microsoft.com/library/default.asp?url=/library/en-us/security/security/creduipromptforcredentials.asp
				//http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dnnetsec/html/dpapiusercredentials.asp?frame=true
				Win32Native.CredUIReturnCodes result = Win32Native.CredUIPromptForCredentialsX(
														ref creditUI, targetName,
														IntPtr.Zero, 0,
														user, Win32Native.MAX_USER_NAME,
														pwd, Win32Native.MAX_PASSWORD,
														ref saveCredentials, flags);

                switch(result)
                {
                    case Win32Native.CredUIReturnCodes.NO_ERROR:
                        StringBuilder usr = new StringBuilder(Win32Native.MAX_USER_NAME);
                        StringBuilder domain = new StringBuilder(Win32Native.MAX_DOMAIN);
                        result = Win32Native.CredUIParseUserNameW(user.ToString(), usr, Win32Native.MAX_USER_NAME, domain, Win32Native.MAX_DOMAIN);
                        if(result == Win32Native.CredUIReturnCodes.NO_ERROR)
                        {
                            if(saveCredentials == 1)
                            {
                                ConfirmCredentials(targetName, true);
                            }
                            return new NetworkCredential(usr.ToString(), pwd.ToString(), domain.ToString());				
                        }
                        else
                        {
                            throw new SecurityException(TranslateReturnCode(result));
                        }
                    case Win32Native.CredUIReturnCodes.ERROR_CANCELLED:
                        return null;
                    default:
                        throw new SecurityException(TranslateReturnCode(result));
                }					
			} 
			finally
			{					
				//Clear pwd data.
				pwd.Remove(0, pwd.Length);
			}
		}
		#endregion

		#region SecureCredential overloads

		/// <summary>
		/// This method creates and displays a configurable dialog box that accepts credentials information from a user.
		/// </summary>
		/// <remarks>
		/// The default 'targetName' is <see cref="DefaultTargetName"/>
		/// </remarks>
		/// <returns><see cref="SecureCredential"/> object with the supplied credentials.</returns>
		public static SecureCredential PromptForSecureCredentials()
		{
			return PromptForSecureCredentials(DefaultTargetName, null, null, IntPtr.Zero);
		}

		/// <summary>
		/// This method creates and displays a configurable dialog box that accepts credentials information from a user.
		/// </summary>
		/// <param name="targetName">Contains the name of the target for the credentials, 
		/// typically a server name. For distributed file system (DFS) connections, 
		/// this string is of the form "servername\sharename".
		/// This parameter is used to identify Target Information when storing and retrieving credentials. 
		/// </param>
		/// <returns><see cref="SecureCredential"/> object with the supplied credentials.</returns>
		public static SecureCredential PromptForSecureCredentials(string targetName)
		{
			return PromptForSecureCredentials(targetName, null, null, IntPtr.Zero);
		}

		/// <summary>
		/// This method creates and displays a configurable dialog box that accepts credentials information from a user.
		/// </summary>
		/// <param name="caption">String containing the title for the dialog box.</param>
		/// <param name="message">String containing a brief message to display in the dialog box.</param>
		/// <returns><see cref="SecureCredential"/> object with the supplied credentials.</returns>
		public static SecureCredential PromptForSecureCredentials(string caption, string message)
		{
			return PromptForSecureCredentials(DefaultTargetName, caption, message);
		}

		/// <summary>
		/// This method creates and displays a configurable dialog box that accepts credentials information from a user.
		/// </summary>
		/// <param name="targetName">Contains the name of the target for the credentials, 
		/// typically a server name. For distributed file system (DFS) connections, 
		/// this string is of the form "servername\sharename".
		/// This parameter is used to identify Target Information when storing and retrieving credentials. 
		/// </param>
		/// <param name="caption">String containing the title for the dialog box.</param>
		/// <param name="message">String containing a brief message to display in the dialog box.</param>
		/// <returns><see cref="SecureCredential"/> object with the supplied credentials.</returns>
		public static SecureCredential PromptForSecureCredentials(string targetName, string caption, string message)
		{
			return PromptForSecureCredentials(targetName, caption, message, IntPtr.Zero);
		}

		/// <summary>
		/// This method creates and displays a configurable dialog box that accepts credentials information from a user.
		/// </summary>
		/// <param name="caption">String containing the title for the dialog box.</param>
		/// <param name="message">String containing a brief message to display in the dialog box.</param>
		/// <param name="owner">Specifies the handle to the parent window of the dialog box.
		/// If this member is NULL, the desktop will be the parent window of the dialog box.
		/// </param>
		/// <returns><see cref="SecureCredential"/> object with the supplied credentials.</returns>
		public static SecureCredential PromptForSecureCredentials(string caption, string message, IntPtr owner)
		{
			return PromptForSecureCredentials(DefaultTargetName, caption, message, owner);
		}

		/// <summary>
		/// This method creates and displays a configurable dialog box that accepts credentials information from a user.
		/// </summary>
		/// <param name="targetName">Contains the name of the target for the credentials, 
		/// typically a server name. For distributed file system (DFS) connections, 
		/// this string is of the form "servername\sharename".
		/// This parameter is used to identify Target Information when storing and retrieving credentials. 
		/// </param>
		/// <param name="caption">String containing the title for the dialog box.</param>
		/// <param name="message">String containing a brief message to display in the dialog box.</param>
		/// <param name="owner">Specifies the handle to the parent window of the dialog box.
		/// If this member is NULL, the desktop will be the parent window of the dialog box.
		/// </param>
		/// <returns><see cref="SecureCredential"/> object with the supplied credentials.</returns>
		/// <permission cref="UIPermission">Demand for <see cref="UIPermissionWindow.SafeTopLevelWindows"/> permission.</permission>
		public static SecureCredential PromptForSecureCredentials(string targetName, string caption, string message, IntPtr owner)
		{
			// Parameter validation
			if( targetName == null )
			{
				throw new ArgumentNullException( "targetName" );
			}
			if( caption == null )
			{
				caption = String.Empty;
			}
			if( message == null )
			{
				message = String.Empty;
			}			

			new UIPermission( UIPermissionWindow.SafeTopLevelWindows ).Demand();

			// Uncommment this lines to use custom bitmap
			// Bitmap credBMP = new Bitmap(@"..\credui.bmp");
			// replace IntPtr.Zero by credBMP.GetHbitmap()
			Win32Native.CREDUI_INFO creditUI = new Win32Native.CREDUI_INFO(owner, caption, message, IntPtr.Zero);
			int saveCredentials = 0;

			StringBuilder user = new StringBuilder(Win32Native.MAX_USER_NAME);
			byte[] pwd = new byte[ Win32Native.MAX_PASSWORD ];
			GCHandle pwdHandle = GCHandle.Alloc(pwd, GCHandleType.Pinned);

			try
			{
				Win32Native.CredUiFlags flags = Win32Native.CredUiFlags.GENERIC_CREDENTIALS |
					Win32Native.CredUiFlags.SHOW_SAVE_CHECK_BOX |
					Win32Native.CredUiFlags.ALWAYS_SHOW_UI |
					Win32Native.CredUiFlags.EXPECT_CONFIRMATION | 
					Win32Native.CredUiFlags.INCORRECT_PASSWORD;

				//For more info see:
				//http://msdn.microsoft.com/library/default.asp?url=/library/en-us/security/security/creduipromptforcredentials.asp
				//http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dnnetsec/html/dpapiusercredentials.asp?frame=true
				Win32Native.CredUIReturnCodes result = Win32Native.CredUIPromptForCredentialsW(
					ref creditUI, targetName,
					IntPtr.Zero, 0,
					user, Win32Native.MAX_USER_NAME,
					pwdHandle.AddrOfPinnedObject(), pwd.Length,
					ref saveCredentials, flags);

				switch(result)
				{
					case Win32Native.CredUIReturnCodes.NO_ERROR:
						StringBuilder usr = new StringBuilder(Win32Native.MAX_USER_NAME);
						StringBuilder domain = new StringBuilder(Win32Native.MAX_DOMAIN);
						result = Win32Native.CredUIParseUserNameW(user.ToString(), usr, Win32Native.MAX_USER_NAME, domain, Win32Native.MAX_DOMAIN);
						if(result == Win32Native.CredUIReturnCodes.NO_ERROR)
						{
							if(saveCredentials == 1)
							{
								ConfirmCredentials(targetName, true);
							}
							unsafe
							{
								return new SecureCredential( usr.ToString(), (char*)pwdHandle.AddrOfPinnedObject().ToPointer(), Win32Native.lstrlenW( pwdHandle.AddrOfPinnedObject() ), domain.ToString() );				
							}
						}
						else
						{
							throw new SecurityException(TranslateReturnCode(result));
						}
					case Win32Native.CredUIReturnCodes.ERROR_CANCELLED:
						return null;
					default:
						throw new SecurityException(TranslateReturnCode(result));
				}					
			} 
			finally
			{
				// Clear pwd data.
				Array.Clear( pwd, 0, pwd.Length );
				
				// Zero out the memory buffer
				Win32Native.ZeroMemory( pwdHandle.AddrOfPinnedObject(), (uint)pwd.Length );

				// Free the allocated handle
				if( pwdHandle.IsAllocated )
				{
					pwdHandle.Free();
				}	
			}
		}
		#endregion

		#region ConfirmCredentials overloads

		/// <summary>
		/// The ConfirmCredentials method is called after PromptForCredentials or PromptForSecureCredentials,
		/// to confirm the validity of the credential harvested. 
		/// </summary>
		/// <remarks>
		/// After calling <see cref="PromptForCredentials()"/> or <see cref="PromptForSecureCredentials()"/>
		/// and before calling <see cref="ConfirmCredentials(bool)"/>, 
		/// the caller must determine whether or not the credentials are actually valid by 
		/// using the credentials to access the resource specified by targetName.
		/// The results of that validation test are passed to <see cref="ConfirmCredentials(bool)"/> in the
		/// bConfirm parameter.
		/// </remarks>
		/// <param name="confirm">Specifies whether the credentials returned from the prompt function are valid.
		/// If TRUE, the credentials are stored in the credential manager as defined by <see cref="PromptForCredentials()"/>.
		/// If FALSE, the credentials are not stored and various pieces of memory are cleaned up.
		/// </param>
		public static void ConfirmCredentials(bool confirm)
		{
			ConfirmCredentials(DefaultTargetName, confirm);
		}

		/// <summary>
		/// The ConfirmCredentials method is called after PromptForCredentials,
		/// to confirm the validity of the credential harvested. 
		/// </summary>
		/// <remarks>
		/// After calling <see cref="PromptForCredentials()"/> and before calling <see cref="ConfirmCredentials(bool)"/>, 
		/// the caller must determine whether or not the credentials are actually valid by 
		/// using the credentials to access the resource specified by targetName.
		/// The results of that validation test are passed to <see cref="ConfirmCredentials(bool)"/> in the
		/// bConfirm parameter.
		/// </remarks>
		/// <param name="targetName">Contains the name of the target for the credentials, typically a domain or server application name.
		///  This must be the same value passed as targetName to <see cref="PromptForCredentials()"/>.
		/// </param>
		/// <param name="confirm">Specifies whether the credentials returned from the prompt function are valid.
		/// If TRUE, the credentials are stored in the credential manager as defined by <see cref="PromptForCredentials()"/>.
		/// If FALSE, the credentials are not stored and various pieces of memory are cleaned up.
		/// </param>
		/// <permission cref="UIPermission">Demand for <see cref="UIPermissionWindow.SafeTopLevelWindows"/> permission.</permission>
		public static void ConfirmCredentials(string targetName, bool confirm)
		{
			if( targetName == null )
			{
				throw new ArgumentNullException( "targetName" );
			}

			new UIPermission( UIPermissionWindow.SafeTopLevelWindows ).Demand();

			Win32Native.CredUIReturnCodes result = Win32Native.CredUIConfirmCredentialsW(targetName, confirm);
				
			if(result != Win32Native.CredUIReturnCodes.NO_ERROR &&
				result != Win32Native.CredUIReturnCodes.ERROR_NOT_FOUND)
			{
				throw new SecurityException(TranslateReturnCode(result));
			}
		}
		#endregion

		#endregion

		#region "Private methods"

		private static string TranslateReturnCode(Win32Native.CredUIReturnCodes result)
		{
			return Resource.ResourceManager[ Resource.MessageKey.CredUIReturn, result ];
		}
		#endregion
	}
}
