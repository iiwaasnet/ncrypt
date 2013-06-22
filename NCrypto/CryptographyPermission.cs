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
using System.Globalization;

namespace NCrypto.Security.Cryptography
{
	#region "CryptographicPermissionFlags enum"
	/// <summary>
	/// Determines whether code that is granted this
	/// permission is able to encrypt data, decrypt data, etc.
	/// </summary>
	[Flags, Serializable]
	public enum CryptographicPermissionFlags
	{
		/// <summary>
		/// Permits Encryption.
		/// </summary>
		Encrypt = 0x01,
		/// <summary>
		/// Permits Decryption.
		/// </summary>
		Decrypt = 0x02,
		/// <summary>
		/// Permits Signature operations.
		/// </summary>
		Sign = 0x04
	}
	#endregion

	/// <summary>
	/// This class is the custom permission implementation used to
	/// authorize cryptographic operations with restricted access.
	/// </summary>
	/// <remarks>
	/// The custom <see cref="CryptographicPermission"/> class maintains the following states:<para/>
	/// CryptographicPermissionFlags: See <see cref="CryptographicPermissionFlags"/>.
	/// </remarks>
	[Serializable]
	public sealed class CryptographicPermission : CodeAccessPermission, IUnrestrictedPermission
	{
		#region Priv. vars & constructors

		internal CryptographicPermissionFlags _permFlag;

		/// <summary>
		/// It is convention for permission types to provide a constructor
		/// that accepts the <see cref="PermissionState"/> enumeration.
		/// </summary>
		/// <param name="state">See <see cref="PermissionState"/>.</param>
		public CryptographicPermission(PermissionState state) : base()
		{
			if( state == PermissionState.Unrestricted )
			{
				_permFlag = CryptographicPermissionFlags.Encrypt | CryptographicPermissionFlags.Decrypt | CryptographicPermissionFlags.Sign;
			}
			else if( state == PermissionState.None )
			{
				_permFlag &= ~(CryptographicPermissionFlags.Encrypt | CryptographicPermissionFlags.Decrypt | CryptographicPermissionFlags.Sign);
			}
			else
			{
				throw new ArgumentException( Resource.ResourceManager[ Resource.MessageKey.InvalidPermissionState, state ] );
			}
		}

		/// <summary>
		/// This constructor allows you to specify the permission level based on
		/// the <see cref="CryptographicPermissionFlags"/> flag.
		/// </summary>
		/// <param name="permflag">See <see cref="CryptographicPermissionFlags"/>.</param>
		public CryptographicPermission(CryptographicPermissionFlags permflag)
		{
			_permFlag = permflag;
		}

		/// <summary>
		/// Base constructor.
		/// </summary>
		public CryptographicPermission() : base()
		{
			_permFlag &= ~CryptographicPermissionFlags.Encrypt | CryptographicPermissionFlags.Decrypt | CryptographicPermissionFlags.Sign;
		}
		#endregion
	
		#region Public Properties
		/// <summary>
		/// Set this property to true to allow encryption.
		/// </summary>
		public bool Encrypt
		{
			set 
			{
				if( true == value )
				{
					_permFlag |= CryptographicPermissionFlags.Encrypt;
				}
				else
				{
					_permFlag &= ~CryptographicPermissionFlags.Encrypt;
				}
			}
			get 
			{
				return ( _permFlag & CryptographicPermissionFlags.Encrypt ).Equals( CryptographicPermissionFlags.Encrypt );
			}
		}
		/// <summary>
		/// Set this property to true to allow decryption.
		/// </summary>
		public bool Decrypt
		{
			set 
			{
				if( true == value )
				{
					_permFlag |= CryptographicPermissionFlags.Decrypt;
				}
				else
				{
					_permFlag &= ~CryptographicPermissionFlags.Decrypt;
				}
			}
			get 
			{
				return ( _permFlag & CryptographicPermissionFlags.Decrypt ).Equals( CryptographicPermissionFlags.Decrypt );
			}
		}
		/// <summary>
		/// Set this property to true to allow execution of Application Processes and Providers.
		/// </summary>
		public bool Sign
		{
			set 
			{
				if( true == value )
				{
					_permFlag |= CryptographicPermissionFlags.Sign;
				}
				else
				{
					_permFlag &= ~CryptographicPermissionFlags.Sign;
				}
			}
			get 
			{
				return ( _permFlag & CryptographicPermissionFlags.Sign ).Equals( CryptographicPermissionFlags.Sign );
			}
		}
		#endregion

		#region IUnrestrictedPermission Members
		/// <summary>
		/// This method returns true if the permission instance is in the unrestricted state.
		/// </summary>
		/// <returns></returns>
		public bool IsUnrestricted()
		{
			bool canEncrypt, canDecrypt, canSign;
			
			canEncrypt = ( this._permFlag & CryptographicPermissionFlags.Encrypt ).Equals( CryptographicPermissionFlags.Encrypt );
			canDecrypt = ( this._permFlag & CryptographicPermissionFlags.Decrypt ).Equals( CryptographicPermissionFlags.Decrypt );
			canSign =    ( this._permFlag & CryptographicPermissionFlags.Sign    ).Equals( CryptographicPermissionFlags.Sign );
		
			return ( canEncrypt && canDecrypt && canSign );
		}
		#endregion

		#region IPermission Members
		/// <summary>
		/// Implement <see cref="IPermission.Copy"/>. This creates an identical copy of the current
		/// permission instance and returns it to the caller.
		/// </summary>
		/// <returns></returns>
		public override IPermission Copy()
		{
			CryptographicPermission permission = new CryptographicPermission( PermissionState.None );
			permission._permFlag = this._permFlag;

			return permission;
		}

		/// <summary>
		/// Implement <see cref="IPermission.Intersect"/>. This returns a permission object that is the
		/// result of the set intersection between the current permission and the supplied permission.
		/// </summary>
		/// <param name="target">See <see cref="IPermission"/>.</param>
		/// <returns></returns>
		public override IPermission Intersect(IPermission target)
		{
			// An input of null indicates a permission with no state.
			// There can be no common state, so the method returns null.
			if( target == null )
			{
				return null;
			}

			if( !target.GetType().Equals( this.GetType() ) )
			{
				throw new ArgumentException( Resource.ResourceManager[ Resource.MessageKey.CryptographicPermissionArgumentException ] );
			}

			// Cast target to an CryptographicPermission.
			CryptographicPermission targetPerm = (CryptographicPermission)target;
  			CryptographicPermissionFlags intersectPerm = this._permFlag & targetPerm._permFlag;

			return new CryptographicPermission( intersectPerm );
		}

		/// <summary>
		/// Implement <see cref="IPermission.Union"/>. This returns a permission object that is the result
		/// of the set union between the current permission and the supplied permission.
		/// </summary>
		/// <param name="target">See <see cref="IPermission"/>.</param>
		/// <returns></returns>
		public override IPermission Union(IPermission target)
		{
			if( target == null )
			{
				return Copy();
			}

			if( !target.GetType().Equals( this.GetType() ) )
			{
				throw new ArgumentException( Resource.ResourceManager[ Resource.MessageKey.CryptographicPermissionArgumentException ] );
			}

			// Cast the target to an CryptographicPermission.
			CryptographicPermission targetPerm = (CryptographicPermission)target;
			CryptographicPermissionFlags unionPerm = this._permFlag | targetPerm._permFlag;

			return new CryptographicPermission(unionPerm);
		}

		/// <summary>
		/// Implement the IPermission.IsSubsetOf. This method returns a bool to indicate
		/// whether or not the current permission is a subset of the supplied permission. To be a subset, every item of state in the current permission must also be in the target permission.
		/// </summary>
		/// <param name="target">See <see cref="IPermission"/>.</param>
		/// <returns></returns>
		public override bool IsSubsetOf(IPermission target)
		{
			// An input of null indicates a permission with no state.
			// The permission can only be a subset if it's in a similar empty state.
			bool canEncrypt, canDecrypt, canSign;
			bool canTargetEncrypt, canTargetDecrypt, canTargetSignature;

			canEncrypt = ( this._permFlag & CryptographicPermissionFlags.Encrypt ).Equals( CryptographicPermissionFlags.Encrypt );
			canDecrypt = ( this._permFlag & CryptographicPermissionFlags.Decrypt ).Equals( CryptographicPermissionFlags.Decrypt );
			canSign =    ( this._permFlag & CryptographicPermissionFlags.Sign    ).Equals( CryptographicPermissionFlags.Sign );

			if (target == null)
			{
				if ( canEncrypt == false && canDecrypt == false && canSign == false )
				{
					return true;
				}
				else
				{
					return false;
				}
			}

			if( !target.GetType().Equals( this.GetType() ) )
			{
				throw new ArgumentException( Resource.ResourceManager[ Resource.MessageKey.CryptographicPermissionArgumentException ] );
			}

			// Cast the target to an EncryptionPermission.
			CryptographicPermission targetPerm = (CryptographicPermission)target;
			
			canTargetEncrypt =   ( targetPerm._permFlag & CryptographicPermissionFlags.Encrypt ).Equals( CryptographicPermissionFlags.Encrypt );
			canTargetDecrypt =   ( targetPerm._permFlag & CryptographicPermissionFlags.Decrypt ).Equals( CryptographicPermissionFlags.Decrypt );
			canTargetSignature = ( targetPerm._permFlag & CryptographicPermissionFlags.Sign    ).Equals( CryptographicPermissionFlags.Sign );

			// Every value set (true) in this permission must be in the target.
			// The following code checks to see if the current permission is a subset
			// of the target. If the current permission has something that the target
			// does not have, it cannot be a subset.
			
			if( canEncrypt == true && canTargetEncrypt == false )
			{
				return false;
			}
			if( canDecrypt == true && canTargetDecrypt == false )
			{
				return false;
			}
			if( canSign == true && canTargetSignature == false )
			{
				return false;
			}
			
			return true;
		}

		#endregion

		#region ISecurityEncodable Members
		/// <summary>
		/// Implement ISecurityEncodable.ToXml. This method convert
		/// instances of a permission object into an XML format.
		/// This methods are used to support serialization.
		/// This is used, for example, when the security attribute is stored in assembly metadata.
		/// </summary>
		/// <returns>Returns a <see cref="SecurityElement"/>.</returns>
		public override SecurityElement ToXml()
		{
			// Create a new element. The tag name must always be IPermission.
			SecurityElement elem = new SecurityElement("IPermission");

			// Determine the fully qualified type name (including the assembly name) of
			// the EncryptionPermission class. (The security system uses this name to
			// locate and load the class.)
			string name = typeof(CryptographicPermission).AssemblyQualifiedName;
			
			// Add attributes for the class name and protocol version.
			// The version must currently be 1.
			elem.AddAttribute("class", name);
			elem.AddAttribute("version", "1" );
			
			if( IsUnrestricted() )
			{
				// Using the Unrestricted attribute is consistent with the
				// built-in .NET Framework permission types and helps keep
				// the encoding compact.
				elem.AddAttribute("Unrestricted", Boolean.TrueString);
			}
			else
			{
				// Encode each state field as an attribute of the Permission element.
				// To compact, encode only nondefault state parameters.
				elem.AddAttribute("Flags", this._permFlag.ToString());
			}
			// Return the completed element.
			return elem;
		}

		/// <summary>
		/// Converts a SecurityElement (or tree of elements) to a permission instance.
		/// </summary>
		/// <param name="elem">See <see cref="SecurityElement"/>.</param>
		public override void FromXml(SecurityElement elem)
		{
			// Check for an unrestricted instance.
			string attrVal = elem.Attribute("Unrestricted");
			
			if (attrVal != null)
			{
				if( String.Compare( attrVal, "true", true, CultureInfo.InvariantCulture) == 0)
				{
					this._permFlag = CryptographicPermissionFlags.Encrypt | CryptographicPermissionFlags.Decrypt | CryptographicPermissionFlags.Sign;
				}
				return;
			}
			
			//Turn off the permission and store flags.
			this._permFlag &= ~(CryptographicPermissionFlags.Encrypt | CryptographicPermissionFlags.Decrypt | CryptographicPermissionFlags.Sign);

			attrVal = elem.Attribute("Flags");
			
			if (attrVal != null)
			{
				if( attrVal.Trim().Length > 0 )
				{
					this._permFlag = (CryptographicPermissionFlags)Enum.Parse(typeof(CryptographicPermissionFlags), attrVal);
				}
			}
		}
		#endregion
	}
}
