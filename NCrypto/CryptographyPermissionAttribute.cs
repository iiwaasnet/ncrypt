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
using System.Diagnostics;
using System.Security;
using System.Security.Permissions;

namespace NCrypto.Security.Cryptography
{
	/// <summary>
	/// Allows security actions for <see cref="CryptographicPermission"/> to be applied to code using 
	/// declarative security. This class cannot be inherited.
	/// </summary>
	[Serializable,
	 AttributeUsage(AttributeTargets.Method |		// Can use on methods
					AttributeTargets.Constructor |  // Can use on constructors
					AttributeTargets.Class |		// Can use on classes
					AttributeTargets.Struct |		// Can use on structures
					AttributeTargets.Assembly,		// Can use at the assembly level
					AllowMultiple = true,			// Can use multiple attribute
													// instances per program element
													// (class, method and so on)
					Inherited = false)]				// Can not be inherited
	public sealed class CryptographicPermissionAttribute : CodeAccessSecurityAttribute
	{
		#region Priv. vars & constructors

		private bool _encrypt = false;
		private bool _decrypt = false;
		private bool _sign = false;

		/// <summary>
		/// Pass the action code back to the base class.
		/// </summary>
		/// <param name="action"></param>
		public CryptographicPermissionAttribute(SecurityAction action) : base(action) {}

		#endregion

		#region Public Properties
		/// <summary>
		/// Permits Encryption.
		/// </summary>
		public bool Encrypt
		{
			get { return _encrypt;}
			set {_encrypt = value;}
		} 

		/// <summary>
		/// Permits Decryption.
		/// </summary>
		public bool Decrypt
		{
			get {return _decrypt;}
			set {_decrypt = value;}
		} 

		/// <summary>
		/// Permits Signature operations.
		/// </summary>
		public bool Sign
		{
			get {return _sign;}
			set {_sign = value;}
		} 
		#endregion

		#region IPermission Members
		/// <summary>
		/// This method creates	a permission object that can then be serialized and persisted with the specified
		/// <see cref="SecurityAction"/> enumeration in an assembly’s metadata.
		/// </summary>
		/// <returns>See <see cref="IPermission"/>.</returns>
		public override IPermission CreatePermission()
		{
			// The runtime automatically provides a property to indicate
			// whether or not an unrestricted instance is required.
			if( Unrestricted || ( _encrypt && _decrypt ) )
			{
				return new CryptographicPermission(PermissionState.Unrestricted);
			}

			// Copy the state from the attribute to the permission object
			CryptographicPermissionFlags perm = 0x0;

			if(_encrypt)
			{
				perm |= CryptographicPermissionFlags.Encrypt;
			}
			if(_decrypt)
			{
				perm |= CryptographicPermissionFlags.Decrypt;
			}
			if(_sign)
			{
				perm |= CryptographicPermissionFlags.Sign;
			}

			// Return the final permission.
			return new CryptographicPermission(perm);
		}
		#endregion
	}
}
