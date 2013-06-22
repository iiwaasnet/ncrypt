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
using System.Web;
using System.Security;
using System.Security.Principal;
using System.Security.Permissions;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Net;
using System.Reflection;
using System.Text;

namespace NCrypto.Security.Cryptography
{
	/// <summary>
	/// Provides static methods that supply helper methods for windows 
	/// accounts authentication and authorization.
	/// </summary>
	public sealed class WinAccessHelper
	{
		#region "LogonType enum"
		/// <summary>
		/// Specifies the type of logon operation to perform.
		/// </summary>
		public enum LogonType
		{
			/// <summary>
			/// This logon type is intended for users who will be interactively using the computer, such as a user being logged on by a terminal server, remote shell, or similar process. This logon type has the additional expense of caching logon information for disconnected operation, and is therefore inappropriate for some client/server applications, such as a mail server.
			/// </summary>
			Interactive = 2,
			/// <summary>
			/// This logon type is intended for high performance servers to authenticate clear text passwords. The LogonUser function does not cache credentials for this logon type.
			/// </summary>
			Network = 3,
			/// <summary>
			/// This logon type is intended for batch servers, where processes may be executing on behalf of a user without their direct intervention; or for higher performance servers that process many clear-text authentication attempts at a time, such as mail or web servers. The LogonUser function does not cache credentials for this logon type.
			/// </summary>
			Batch = 4,
			/// <summary>
			/// Indicates a service-type logon. The account provided must have the service privilege enabled.
			/// </summary>
			Service = 5,
			/// <summary>
			/// This logon type is intended for GINA DLLs logging on users who will be interactively using the computer. This logon type allows a unique audit record to be generated that shows when the workstation was unlocked.
			/// </summary>
			Unlock = 7,
			/// <summary>
			/// Windows XP/2000:  This logon type preserves the name and password in the authentication packages, allowing the server to make connections to other network servers while impersonating the client. This allows a server to accept clear text credentials from a client, call LogonUser, verify that the user can access the system across the network, and still communicate with other servers.
			/// </summary>
			NetworkClearText = 8,
			/// <summary>
			/// Windows XP/2000:  This logon type allows the caller to clone its current token and specify new credentials for outbound connections. The new logon session has the same local identity, but uses different credentials for other network connections.
			/// This logon type is supported only by the LOGON32_PROVIDER_WINNT50 logon provider.
			/// </summary>
			NewCredentials = 9
		}
		#endregion

		#region "Private Members & Constructors"

		/// <summary>
		/// PermissionSet to assert
		/// </summary>
		private static PermissionSet _assertedPermissions = new PermissionSet( PermissionState.None );

		private const int GroupsBufferCapacity = 1024;

		private WinAccessHelper(){}
		
		static WinAccessHelper()
		{
			_assertedPermissions.AddPermission( new SecurityPermission( SecurityPermissionFlag.UnmanagedCode ) );
			_assertedPermissions.AddPermission(	new EnvironmentPermission( PermissionState.Unrestricted ) );
		}

		#endregion

		#region "Authentication Methods"
		/// <summary>
		/// Gets the IIS Anonimous user WindowsIdentity.
		/// </summary>
		/// <remarks>
		/// Use IIS to configure the anonymous user account as the trusted alternate identity.<para/>
		/// Then use this method to get a <see cref="WindowsIdentity"/> instance with impersonation token using the anonymous IIS account.<para/>		/// 
		/// </remarks>
		/// <note type="note">
		/// This approach assumes Forms or Passport authentication where your application’s virtual
		/// directory is configured in IIS to support anonymous access.<para/>
		/// The code demands the unmanaged code permission SecurityPermission(SecurityPermissionFlag.UnmanagedCode),<para/>
		/// which is granted only to fully trusted Web applications.
		/// </note>
		/// <exception cref="HttpException">Http current context is null.</exception>
		/// <example>If you use this code, use the following <b>&lt;identity&gt;</b> configuration:
		/// <code lang="C#">
		/// &lt;identity impersonate="false" /&gt;
		/// </code>
		/// </example>
		/// <returns>A <see cref="WindowsIdentity"/> instance for the account used for anonymous access.</returns>
		/// <permission cref="SecurityPermission">Demand for <see cref="SecurityPermissionFlag.ControlPrincipal"/> permission flag.</permission>
		public static WindowsIdentity LogonUser()
		{
			HttpContext context = HttpContext.Current;
			
			if(context == null)
			{
				throw new HttpException( Resource.ResourceManager[ Resource.MessageKey.NullContextException ] );
			}

			// Demand permissions
			new SecurityPermission( SecurityPermissionFlag.ControlPrincipal ).Demand();
			// Assert permissions
			_assertedPermissions.Assert();

			try
			{
				// Get the service provider from the context
				IServiceProvider iServiceProvider = context as IServiceProvider;
			
				//Get a Type which represents an HttpContext
				Type httpWorkerRequestType = typeof(HttpWorkerRequest);
			
				// Get the HttpWorkerRequest service from the service provider
				// NOTE: When trying to get a HttpWorkerRequest type from the HttpContext
				// unmanaged code permission is demanded.
				HttpWorkerRequest httpWorkerRequest = iServiceProvider.GetService(httpWorkerRequestType) as HttpWorkerRequest;
			
				// Get the token passed by IIS
				IntPtr ptrUserToken = httpWorkerRequest.GetUserToken();
			
				// Create a WindowsIdentity from the token
				return new WindowsIdentity(ptrUserToken, "NTLM", WindowsAccountType.Normal, true);		
			}
			finally
			{
				CodeAccessPermission.RevertAssert();
			}
		}

		/// <summary>
		/// Logon a user with the specified credentials.
		/// </summary>
		/// <param name="userName">The user name associated with the credentials.</param>
		/// <param name="password">The password for the user name associated with the credentials.</param>
		/// <returns>The <see cref="WindowsIdentity"/> of the logged on account.</returns>
		/// <permission cref="SecurityPermission">Demand for <see cref="SecurityPermissionFlag.ControlPrincipal"/> permission flag.</permission>
		/// <exception cref="ArgumentException">Unable to logon</exception>
		public static WindowsIdentity LogonUser(string userName, string password)
		{
			return LogonUser( new NetworkCredential( userName, password ), LogonType.Interactive);
		}

		/// <summary>
		/// Logon a user with the specified credentials.
		/// </summary>
		/// <param name="userName">The user name associated with the credentials.</param>
		/// <param name="password">The password for the user name associated with the credentials.</param>
		/// <param name="domain">The domain associated with these credentials.</param>
		/// <returns>The <see cref="WindowsIdentity"/> of the logged on account.</returns>
		/// <permission cref="SecurityPermission">Demand for <see cref="SecurityPermissionFlag.ControlPrincipal"/> permission flag.</permission>
		/// <exception cref="ArgumentException">Unable to logon</exception>
		public static WindowsIdentity LogonUser(string userName, string password, string domain)
		{
			return LogonUser( new NetworkCredential( userName, password, domain ), LogonType.Interactive);
		}

		/// <summary>
		/// Logon a user with the specified credentials.
		/// </summary>
		/// <param name="credentials">Credentials for logon. See <see cref="NetworkCredential"/>.</param>
		/// <returns>The <see cref="WindowsIdentity"/> of the logged on account.</returns>
		/// <permission cref="SecurityPermission">Demand for <see cref="SecurityPermissionFlag.ControlPrincipal"/> permission flag.</permission>
		/// <exception cref="ArgumentException">Unable to logon</exception>
		public static WindowsIdentity LogonUser(NetworkCredential credentials)
		{
			return LogonUser(credentials, LogonType.Interactive);
		}

		/// <summary>
		/// Logon a user with the specified credentials.
		/// </summary>
		/// <param name="credentials">Credentials for logon. See <see cref="NetworkCredential"/>.</param>
		/// <param name="logontype">See <see cref="LogonType"/>.</param>
		/// <returns>The <see cref="WindowsIdentity"/> of the logged on account.</returns>
		/// <permission cref="SecurityPermission">Demand for <see cref="SecurityPermissionFlag.ControlPrincipal"/> permission flag.</permission>
		/// <exception cref="ArgumentException">Unable to logon</exception>
		public static WindowsIdentity LogonUser(NetworkCredential credentials, LogonType logontype)
		{
			// Parameter validation
			if( credentials == null )
			{
				throw new ArgumentException( "credentials" );
			}

			// Demand permissions
			new SecurityPermission( SecurityPermissionFlag.ControlPrincipal ).Demand();
			// Assert permissions
			_assertedPermissions.Assert();

			// initialize tokens
			IntPtr pExistingTokenHandle = IntPtr.Zero;
			IntPtr pDuplicateTokenHandle = IntPtr.Zero;
			
			string domain = credentials.Domain;
			if(domain == null || domain.Length == 0)
			{
				domain = Environment.MachineName;
			}
			
			bool returnValue = false;

			try
			{				
				returnValue = Win32Native.LogonUser(credentials.UserName,
													domain, 
													credentials.Password, 
													(int)logontype, 
													Win32Native.LOGON32_PROVIDER_DEFAULT, 
													ref pExistingTokenHandle);  

				if( returnValue && pExistingTokenHandle != IntPtr.Zero )
				{
					returnValue = Win32Native.DuplicateToken(pExistingTokenHandle, (int)Win32Native.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, ref pDuplicateTokenHandle);
					// did DuplicateToken fail?
					if( returnValue )
					{						
						// create new identity using new primary token
						return new WindowsIdentity(pDuplicateTokenHandle, "NTLM", WindowsAccountType.Normal, true);
					}
					else
					{
						throw new Win32Exception( Marshal.GetLastWin32Error() );
					}
				}
				else
				{
					throw new Win32Exception( Marshal.GetLastWin32Error() );
				}
			}
			catch(Win32Exception wex)
			{
				//Add detailed description
				throw new ArgumentException( Resource.ResourceManager[ Resource.MessageKey.LogonUserException,				 
																	    domain, 
																	    credentials.UserName, 
																	    logontype.ToString(), 
																		Environment.NewLine, 
																		wex.Message, 
																		Environment.MachineName, 
																		WindowsIdentity.GetCurrent().Name] );
			}
			finally
			{
				// close handles
				if( pExistingTokenHandle != IntPtr.Zero )
				{
					Win32Native.CloseHandle(pExistingTokenHandle);
				}
				if( pDuplicateTokenHandle != IntPtr.Zero )
				{
					Win32Native.CloseHandle(pDuplicateTokenHandle);
				}
				// Revert permission (Not strictly necessary but a good practice indeed.)
				System.Security.CodeAccessPermission.RevertAssert();
			}			
		}
		#endregion

        #region "Authorization Methods"

        /// <summary>
        /// Test and assert for membership in any role within roles array.
        /// </summary>
        /// <param name="principal">See <see cref="WindowsPrincipal"/>.</param>
        /// <param name="roles">Roles array to check.</param>
        /// <returns></returns>
        public static bool IsInAnyRole(WindowsPrincipal principal, string[] roles)
        {
			// Parameter validation
			if( principal == null )
			{
				throw new ArgumentNullException( "principal" );
			}
			if( roles == null )
			{
				throw new ArgumentNullException( "roles" );
			}

            bool result = false;

            for(int i=0;i<roles.Length;i++)
            {
                if(principal.IsInRole(roles[i]))
                {
                    result = true;
                    break;
                }
            }

            return result;
        }

		/// <summary>
		/// Gets the roles (user groups) of a <see cref="WindowsPrincipal"/> instance.
		/// </summary>
		/// <param name="principal">The <see cref="WindowsPrincipal"/> to get the roles.</param>
		/// <returns>Roles array.</returns>
		/// <permission cref="SecurityPermission">Demand for <see cref="SecurityPermissionFlag.ControlPrincipal"/> permission flag.</permission>
		/// <exception cref="ArgumentException">Unable to logon</exception>
		public static string[] Roles( WindowsPrincipal principal )
		{
			if( principal == null )
			{
				throw new ArgumentNullException( "principal" );
			}

			return Roles( (WindowsIdentity)principal.Identity );
		}

		/// <summary>
		/// Gets the roles (user groups) of a <see cref="WindowsIdentity"/> instance.
		/// </summary>
		/// <param name="identity">The <see cref="WindowsIdentity"/> to get the roles.</param>
		/// <returns>Roles array.</returns>
		/// <permission cref="SecurityPermission">Demand for <see cref="SecurityPermissionFlag.ControlPrincipal"/> permission flag.</permission>
		/// <exception cref="ArgumentException">Unable to logon</exception>
		public static string[] Roles( WindowsIdentity identity )
		{
			if( identity == null )
			{
				throw new ArgumentNullException( "identity" );
			}

			if( identity.Name.Length < 1 )
			{
				return new string[0];
			}

			#region ASP.NET API method
//			StringBuilder allGroups = new StringBuilder(GroupsBufferCapacity);
//			StringBuilder error = new StringBuilder(GroupsBufferCapacity);
//			int result = Win32Native.GetGroupsForUser(identity.Token, allGroups, allGroups.Capacity, error, error.Capacity);
//
//			if( result < 0 )
//			{
//				allGroups = new StringBuilder(-result);
//				result = Win32Native.GetGroupsForUser(identity.Token, allGroups, -result, error, error.Capacity);
//			}
//			if( result <= 0 )
//			{
//				throw new Win32Exception( Marshal.GetLastWin32Error(), error.ToString() );
//			}
//
//			return allGroups.ToString().Split('\t');
			#endregion

			new SecurityPermission( SecurityPermissionFlag.ControlPrincipal ).Demand();

			// Note: this kind of hack implementation is temporal and might be
			// replaced with the Windows Security API.
			// We might use PInvoke to call Win32 GetTokenInformation API to 
			// TOKEN_INFORMATION_CLASS.TokenGroups, passing in the 
			// principal.Identity.Token as the parameter as the token handle.
			// However, this is the easiest way for getting roles but beware of breaking 
			// changes in future versions of the Base Class Library.

			string[] roles = (string[])CallPrivateMethod( identity, "GetRoles" );
			
			return roles;
		}

        #endregion

		#region "Private Methods"

		/// <summary>
		/// This should be used with caution and might not be granted the required
		/// permissions to run.
		/// </summary>
		[ReflectionPermission( SecurityAction.Assert, MemberAccess=true)]
		private static object CallPrivateMethod(object o, string methodName) 
		{
			Type t = o.GetType();
			MethodInfo mi = t.GetMethod(methodName,
				BindingFlags.NonPublic |
				BindingFlags.Instance);

			if (mi == null)
			{
				throw new System.Reflection.ReflectionTypeLoadException(null,null, Resource.ResourceManager[ Resource.MessageKey.ReflectionTypeLoadException, t.FullName, methodName ] );
			}

			return mi.Invoke(o, null);
		}

		#endregion

	}
}
