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
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace NCrypto.Security.Cryptography
{
	/// <summary>
	/// Helper class for symmetric keys (Key and Salt) genereation.
	/// </summary>
	internal class DerivedKeys : IDisposable
	{
		#region "Private fields"

		// For keys storage
		private byte[] _key;
		private byte[] _iv;
		private byte[] _salt;
        
		// For pinned data allocations
		private GCHandle _kh;
		private GCHandle _vh;
		private GCHandle _sh;

		// Track whether Dispose has been called.
		private bool _disposed = false;

		// WARNING: 218 iterations with SHA256(~18 bits extra computational entropy)
		// might cause a performance issue.
		private const int PasswordDeriveBytesIterations = 218;

		private const string PwdDeriveHashName = "SHA256";

		#endregion

		#region "Constructors & Finalizers"

		/// <summary>
		/// Initaialize the <see cref="DerivedKeys"/> instance with the passphrase, the
		/// IV and the salt.
		/// </summary>
		/// <param name="passphrase">User passprhase</param>
		/// <param name="algorithm">See <see cref="SymmetricAlgorithm"/>.</param>
		public DerivedKeys( string passphrase, SymmetricAlgorithm algorithm )
		{
			_salt = CryptoHelper.ComputeRandomBytes( algorithm.KeySize >> 3 );

			// Pin the keys in memory to prevents the garbage collector from moving the 
			// object and hence undermines the efficiency of the garbage collector
			// threfore, we should call dispose after using these keys.
			PinKeys( passphrase, algorithm.BlockSize >> 3 );	
		}

		/// <summary>
		/// Initialize the <see cref="DerivedKeys"/> instance with the passphrase, the
		/// IV and the salt.
		/// </summary>
		/// <param name="passphrase">User passprhase</param>
		/// <param name="algorithm">See <see cref="SymmetricAlgorithm"/>.</param>
		/// <param name="packedData">The packed data (salt+data) bytes.</param>
		public DerivedKeys( string passphrase, SymmetricAlgorithm algorithm, ref byte[] packedData )
		{
			//Extract salt from packedKeys
			SplitArray unpacked = Utility.SplitArrays( packedData, algorithm.KeySize >> 3 );
	
			_salt = unpacked.FirstArray();

			// Pin the keys in memory to prevents the garbage collector from moving the 
			// object and hence undermines the efficiency of the garbage collector
			// threfore, we should call dispose after using these keys.
			PinKeys( passphrase, algorithm.BlockSize >> 3 );	

			// Return clean data blob
			packedData = unpacked.SecondArray();
		}

		/// <summary>
		/// Class Finalizer.
		/// This destructor will run only if the Dispose method does not get called.
		/// </summary>
		~DerivedKeys()
		{
			// Do not re-create Dispose clean-up code here.
			// Calling Dispose(false) is optimal in terms of
			// readability and maintainability.
			Dispose( false );
		}


		#endregion

		#region "Public properties"

		/// <summary>
		/// Gets key for the symmetric algorithm.
		/// </summary>
		public byte[] Key 
		{
			get{ return _key; }
		}		

		/// <summary>
		/// Gets IV for the symmetric algorithm.
		/// </summary>
		/// <remarks>
		/// The initialization vector (IV) is a random sequence of bytes pre-appended to 
		/// the plaintext before the initial block is encrypted. The IV plays a big role 
		/// by reducing the chances of successfully factoring the key using a chosen 
		/// plaintext attack. The IV does not need to be secret but should vary from 
		/// session to session.
		/// </remarks>
		public byte[] IV 
		{
			get{ return _iv; }
		}		

		/// <summary>
		/// Gets salt value for deriving a cryptographic key.
		/// </summary>
		public byte[] Salt 
		{
			get{ return _salt; }
		}

		#endregion

		#region "IDisposable Members"

		/// <summary>
		/// Performs application-defined tasks associated with freeing, releasing, or 
		/// resetting unmanaged resources.
		/// </summary>
		public void Dispose()
		{
			Dispose( true );

			// This object will be cleaned up by the Dispose method.
			// Therefore, you should call GC.SupressFinalize to
			// take this object off the finalization queue 
			// and prevent finalization code for this object
			// from executing a second time.
			GC.SuppressFinalize(this);
		}

		/// <summary>
		/// Internal Dispose.
		/// </summary>
		/// <remarks>
		/// Dispose(bool disposing) executes in two distinct scenarios.
		/// If disposing equals true, the method has been called directly
		/// or indirectly by a user's code. Managed and unmanaged resources
		/// can be disposed.
		/// If disposing equals false, the method has been called by the 
		/// runtime from inside the finalizer and you should not reference 
		/// other objects. Only unmanaged resources can be disposed.
		/// </remarks>
		protected void Dispose(bool disposing)
		{
			// Check to see if Dispose has already been called.
			if(!this._disposed)
			{
				// If disposing equals true, dispose all managed 
				// and unmanaged resources.
				if( disposing )
				{
					if( _key != null )
					{
						Array.Clear( _key, 0, _key.Length );
						_key = null;
					}

					if( _salt != null )
					{
						Array.Clear( _salt, 0, _salt.Length );
						_salt = null;
					}

					if( _iv != null )
					{
						Array.Clear( _iv, 0, _iv.Length );
						_iv = null;
					}
				}

				// Call the appropriate methods to clean up 
				// unmanaged resources here.
				// If disposing is false, 
				// only the following code is executed.
				if( _kh.IsAllocated )
				{
					_kh.Free();
				}

				if( _sh.IsAllocated )
				{
					_sh.Free();
				}

				if( _vh.IsAllocated )
				{
					_vh.Free();
				}
			}
			_disposed = true;
		}

		#endregion

		#region "Private methods"

		private void PinKeys( string passphrase, int ivLength )
		{
			PasswordDeriveBytes pdb = new PasswordDeriveBytes( passphrase, _salt, PwdDeriveHashName, PasswordDeriveBytesIterations );
			_key = pdb.GetBytes( _salt.Length );
			_iv = pdb.GetBytes( ivLength );

			_kh = GCHandle.Alloc( _key, GCHandleType.Pinned );
			_sh = GCHandle.Alloc( _salt, GCHandleType.Pinned );
			_vh = GCHandle.Alloc( _iv, GCHandleType.Pinned );
		}
		#endregion
	}
}
