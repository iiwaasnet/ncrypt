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
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security.Permissions;

namespace NCrypto.Security.Cryptography
{

	/// <summary>
	/// Provides static methods that supply helper utilities for manipulating cryptographic primitives access. 
	/// This class cannot be inherited.
	/// </summary>
	/// <remarks>
	/// Cryptographic primitives are basic mathematical operations on which cryptographic
	/// schemes can be built. They are intended for implementation in hardware or as software
	/// modules, and are not intended to provide security apart from a scheme.
	/// Four types of primitive are specified in this class, organized in pairs: encryption and
	/// decryption, signture and verification, hashing operations and random number generation.
	/// </remarks>
	public sealed class CryptoHelper
	{
		#region "Private Fields & Constructors"

		/// <summary>
		/// Cryptographic Random Number Generator (RNG) for random data generaton.
		/// </summary>
		private static RNGCryptoServiceProvider _rng = new RNGCryptoServiceProvider();

		/// <summary>
		/// Default CspParameters field.
		/// </summary>
		private static CspParameters _defaultCspParameters = new CspParameters();

		// Since this class provides only static methods, make the default constructor private to prevent 
		// instances from being created with "new CryptoHelper()".
		private CryptoHelper() {}

		/// <summary>
		/// Static initializer.
		/// </summary>
		static CryptoHelper()
		{
			// Default KeyContainerName (this class is only for reading, 
			// so we shouldn't have any threading issues.
			_defaultCspParameters.KeyContainerName = AppDomain.CurrentDomain.FriendlyName;
			
			// If we are running under an interactive logged on account
			// use the default DefaultKeyContainer (Current User) 
			// otherwise use the LocalMachine store.
			if( Environment.UserInteractive )
			{
				_defaultCspParameters.Flags = CspProviderFlags.UseDefaultKeyContainer;
			}
			else
			{
				_defaultCspParameters.Flags = CspProviderFlags.UseMachineKeyStore;
			}
		}

		#endregion

		#region "Public Properties"

		/// <summary>
		/// Default Csp parameters used in the Default Asymmetric algorithm 
		/// (<see cref="RSACryptoServiceProvider"/>).
		/// </summary>
		public static CspParameters DefaultCspParameters
		{
			get
			{
				return _defaultCspParameters;
			}
		}

		/// <summary>
		/// Instance of <see cref="RSACryptoServiceProvider"/> loaded with the <see cref="DefaultCspParameters"/> value.
		/// </summary>
		/// <permission cref="CryptographicPermission">Demand for sign permission.</permission>
		public static RSACryptoServiceProvider RsaInstance
		{
			get
			{
				new CryptographicPermission( CryptographicPermissionFlags.Sign ).Demand();
				new SecurityPermission( SecurityPermissionFlag.UnmanagedCode ).Assert();

				RSACryptoServiceProvider rsa = new RSACryptoServiceProvider( _defaultCspParameters );
				rsa.PersistKeyInCsp = true;
				return rsa;
			}
		}
		#endregion

		#region "Public methods"

		#region "Encryption methods"

		/// <summary>
		/// Encrypt a string into a base64 encoded string using the 
		/// <see cref="ProtectedData.Protect(string)"/> method with <see cref="DataProtectionScope.LocalMachine"/> scope. 
		/// </summary>
		/// <param name="plainText">The clear text to encrypt.</param>
		/// <returns>The encrypted data encoded in base 64.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for encryption permission.</permission>
		public static string Encrypt( string plainText )
		{
			return ProtectedData.Protect( plainText );
		}

		/// <summary>
		/// Encrypt a byte array using the <see cref="ProtectedData.Protect(string)"/> method with <see cref="DataProtectionScope.LocalMachine"/> scope. 
		/// </summary>
		/// <param name="plainText">The clear text to encrypt.</param>
		/// <returns>The encrypted data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for encryption permission.</permission>
		public static byte[] Encrypt( byte[] plainText )
		{
			return ProtectedData.Protect( plainText );
		}

		/// <summary>
		/// Encrypt a string into a base64 encoded string using the 
		/// default algoritm (see <see cref="SymmetricAlgorithm.Create()"/> 
		/// </summary>
		/// <remarks>
		/// The IV and salt used to derive the symmetric key will be appended at the 
		/// beginning of the encryptrd data.
		/// </remarks>
		/// <param name="plainText">The clear text to encrypt.</param>
		/// <param name="password">The password for decryption.</param>
		/// <returns>The encrypted data encoded in base 64.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for encryption permission.</permission>
		public static string Encrypt( string plainText, string password )
		{
			// Instance of the default implementation of a symmetric algorithm.
			// This is Rijndael by default.
			SymmetricAlgorithm algorithm = new RijndaelManaged(); // SymmetricAlgorithm.Create();

			try
			{
				return Encrypt( plainText, password, algorithm );
			}
			finally
			{
				// Scrub data maintained by the crypto class
				algorithm.Clear();
			}
		}

		/// <summary>
		/// Encrypt a string into a base64 encoded string using the 
		/// selected algoritm. 
		/// </summary>
		/// <remarks>
		/// The IV and salt used to derive the symmetric key will be appended at the 
		/// beginning of the encryptrd data.
		/// </remarks>
		/// <param name="plainText">The clear text to encrypt.</param>
		/// <param name="password">The password to use.</param>
		/// <param name="algorithm">The <see cref="SymmetricAlgorithm"/> algorithm to use.</param>
		/// <returns>The encrypted data encoded in base 64.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for encryption permission.</permission>
		public static string Encrypt( string plainText, string password, SymmetricAlgorithm algorithm )
		{
			// Parameter checks 
			if( plainText == null )
			{
				throw new ArgumentNullException( "plainText" );
			}
			if( password == null || password.Length == 0 )
			{
				throw new ArgumentNullException( "password" );
			}
			if( algorithm == null )
			{
				throw new ArgumentNullException( "algorithm" );
			}

			// Turn the input string into a byte array.  
			byte[] userData = Utility.DefaultEncoding.GetBytes( plainText );

			try
			{
				// We need to turn the password into the Key and IV for the alg.
				using(DerivedKeys keys = new DerivedKeys( password, algorithm ))
				{
					// Load the keys into the algorithm
					algorithm.Key = keys.Key;

					// We assume that the algorithm is operating in CBC mode (Cipher Block Chaining)
					// we load its IV
					algorithm.IV = keys.IV;

					// Proceed to encrypt.
					byte[] cipherText = Encrypt( userData, algorithm );

					// Save the IV and salt with the encrypted string
					// salt + iv + cipherdata
					// Encode and return
					return Convert.ToBase64String( Utility.JoinArrays( keys.Salt , cipherText ) );
				}

			}
			finally
			{
				// Erase bytes
				Array.Clear( userData, 0, userData.Length );
			}
		}

		/// <summary>
		/// Encrypt a byte array using the selected algorithm. 
		/// </summary>
		/// <remarks>
		/// The IV and salt used to derive the symmetric key will be appended at the 
		/// beginning of the encryptrd data.
		/// </remarks>
		/// <param name="plainText">The clear text to encrypt.</param>
		/// <param name="algorithm">The <see cref="SymmetricAlgorithm"/> algorithm to use.</param>
		/// <returns>The encrypted data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for encryption permission.</permission>
		public static byte[] Encrypt( byte[] plainText, SymmetricAlgorithm algorithm )
		{
			// Verify parameters
			if( plainText == null )
			{
				throw new ArgumentNullException( "plainText" );
			}

			if( algorithm == null )
			{
				throw new ArgumentNullException( "algorithm" );
			}

			// Demand Permission
			new CryptographicPermission( CryptographicPermissionFlags.Encrypt ).Demand();

			// Create a MemoryStream that is going to accept the encrypted bytes
			MemoryStream ms = new MemoryStream();
			
			using( CryptoStream cs = new CryptoStream( ms, algorithm.CreateEncryptor(), CryptoStreamMode.Write) )
			{
				// Write the data and make it do the encryption 
				cs.Write( plainText, 0, plainText.Length );
				cs.Close(); 				
				return ms.ToArray(); 
			}
		}

		#region "Asymmetric encryption"

		/// <summary>
		/// Encrypt a string using an implementation of the <see cref="RSA"/> algorithm. 
		/// </summary>
		/// <remarks>
		/// Asymmentric encription is not intended to use for large input data.
		/// Use symmentric encryption for this scenarios.
		/// </remarks>
		/// <param name="plainText">The clear text to encrypt.</param>
		/// <param name="parameters">The <see cref="RSAParameters"/> parameters to use.</param>
		/// <returns>The encrypted data encoded in hexadecimal.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for encryption permission.</permission>
		public static string Encrypt( string plainText, RSAParameters parameters )
		{
			return Utility.ToHexString( Encrypt( Utility.DefaultEncoding.GetBytes( plainText ), parameters, false ) );
		}

		/// <summary>
		/// Encrypt a byte array using an implementation of the <see cref="RSA"/> algorithm. 
		/// </summary>
		/// <remarks>
		/// Asymmentric encription is not intended to use for large input data.
		/// Use symmentric encryption for this scenarios.
		/// </remarks>
		/// <param name="plainText">The clear text to encrypt.</param>
		/// <param name="parameters">The <see cref="RSAParameters"/> parameters to use.</param>
		/// <param name="oaep">true to perform direct RSA encryption using OAEP 
		/// padding (only available on a computer running Microsoft Windows XP or 
		/// later); otherwise, false to use PKCS#1 v1.5 padding.</param>
		/// <returns>The encrypted data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for encryption permission.</permission>
		public static byte[] Encrypt( byte[] plainText, RSAParameters parameters, bool oaep)
		{
			// Verify parameters
			if( plainText == null )
			{
				throw new ArgumentNullException( "plainText" );
			}
			if( parameters.Modulus == null || parameters.Exponent == null )
			{
				throw new ArgumentNullException( "parameters.Modulus/parameters.Exponent" );
			}

			// Demand Permission
			new CryptographicPermission( CryptographicPermissionFlags.Encrypt ).Demand();
			
			RSACryptoServiceProvider rsa = RsaInstance;

			try
			{
				// Import the RSA Key information
				rsa.ImportParameters( parameters );

				// Check if we are able to encrpyt in one pass.
				int blockSize = (rsa.KeySize >> 3) - 11;
			
				if(plainText.Length <= blockSize)
				{
					return rsa.Encrypt( plainText, oaep ); //Set oaep=true for Windows XP or better.
				} 
				else
				{
					// The PlainText (data) will need to be broken into segments of 
					// size (ModulusSize=rsa.KeySize/8) - 11
					// Each of these segments will be encrypted separately 
					// and will return encrypted data equal to the ModulusSize 
					// (with at least 11 bytes of padding).
					int modulusSize = blockSize + 11;
				
					using( MemoryStream msin = new MemoryStream(plainText) )
					using( MemoryStream msout = new MemoryStream(blockSize) )
					{
						byte[] buffer = new byte[blockSize];
						int bytesRead;
				
						do 
						{
							bytesRead = msin.Read(buffer, 0, blockSize);
							if(bytesRead == blockSize)
							{
								msout.Write( rsa.Encrypt(buffer, oaep), 0, modulusSize );
							}
							else
							{
								byte[] final = new byte[bytesRead];
								Array.Copy(buffer, final, bytesRead); 
								msout.Write( rsa.Encrypt(final, oaep), 0, modulusSize );
							}						
						} while (bytesRead == blockSize);

						return msout.ToArray();
					}
				}
			}
			finally
			{
				rsa.Clear();
			}
		}

		#endregion

		#endregion

		#region "Decryption methods"

		/// <summary>
		/// Decrypt a base64 encoded string into a string using the 
		/// <see cref="ProtectedData.Unprotect(string)"/> method with <see cref="DataProtectionScope.LocalMachine"/> scope. 
		/// </summary>
		/// <param name="cipherText">The data to decrypt.</param>
		/// <returns>The clear text data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static string Decrypt( string cipherText )
		{
			return ProtectedData.Unprotect( cipherText );
		}

		/// <summary>
		/// Decrypt a byte array using the <see cref="ProtectedData.Unprotect(string)"/> method with <see cref="DataProtectionScope.LocalMachine"/> scope. 
		/// </summary>
		/// <param name="cipherText">The data to decrypt.</param>
		/// <returns>The clear text data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static byte[] Decrypt( byte[] cipherText )
		{
			return ProtectedData.Unprotect( cipherText, null, DataProtectionScope.LocalMachine );
		}

		/// <summary>
		/// Decrypt a string from a base64 encoded string using the 
		/// default algoritm (see <see cref="SymmetricAlgorithm.Create()"/> 
		/// </summary>
		/// <remarks>
		/// The IV and salt used to derive the symmetric key will be taken from the 
		/// beginning of the encrypted data.
		/// </remarks>
		/// <param name="cipherText">The encrypted text to decrypt.</param>
		/// <param name="password">The password for decryption.</param>
		/// <returns>The clear text data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static string Decrypt( string cipherText, string password )
		{
			// Creates the default algorithm (Rijndael)
			SymmetricAlgorithm algorithm = new RijndaelManaged(); // SymmetricAlgorithm.Create();

			try
			{
				// Instance the default implementation of a symmetric algorithm.
				// This is usually Rijndael by default.
				return Decrypt( cipherText, password, algorithm );
			}
			finally
			{
				// Scrub data maintained by the crypto class
				algorithm.Clear();
			}
		}

		/// <summary>
		/// Decrypt a string from a base64 encoded string using the 
		/// selected algoritm.
		/// </summary>
		/// <remarks>
		/// The IV and salt used to derive the symmetric key will be taken from the 
		/// beginning of the encrypted data.
		/// </remarks>
		/// <param name="cipherText">The encrypted text to decrypt.</param>
		/// <param name="password">The password for decryption.</param>
		/// <param name="algorithm">The <see cref="SymmetricAlgorithm"/> algorithm to use.</param>
		/// <returns>The clear text data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static string Decrypt( string cipherText, string password, SymmetricAlgorithm algorithm )
		{
			// Parameter checks 
			if( cipherText == null || cipherText.Length == 0 )
			{
				throw new ArgumentNullException( "cipherText" );
			}
			if( password == null )
			{
				throw new ArgumentNullException( "password" );
			}
			if( algorithm == null )
			{
				throw new ArgumentNullException( "algorithm" );
			}
			if( !Utility.IsBase64Encoding( cipherText ) )
			{
				throw new ArgumentException( Resource.ResourceManager[ Resource.MessageKey.Base64EncodingException, cipherText ] );
			}

			// Turn the input Base64 string into a byte array. 
			byte[] cipherBytes = Convert.FromBase64String(cipherText); 

			byte[] clearText = null;

			try
			{
				// We need to turn the password into the Key and IV for the alg.
				// We get the cipher bytes without the keys as well.
				using(DerivedKeys keys = new DerivedKeys( password, algorithm, ref cipherBytes ))
				{
					// Load the keys into the algorithm
					algorithm.Key = keys.Key;

					// We assume that the algorithm is operating in CBC mode (Cipher Block Chaining)
					// we load its IV
					algorithm.IV = keys.IV;

					// Proceed to decrypt and encode.
					clearText = Decrypt( cipherBytes, algorithm );

					// Encode and return
					return Utility.DefaultEncoding.GetString( clearText );
				}

			}
			finally
			{
				// Erase bytes
				if( clearText != null )
				{
					Array.Clear( clearText, 0, clearText.Length );
				}
			}
		}

		/// <summary>
		/// Decrypt a byte array using the default algoritm (see <see cref="SymmetricAlgorithm.Create()"/> 
		/// </summary>
		/// <remarks>
		/// The IV and salt used to derive the symmetric key will be taken from the 
		/// beginning of the encrypted data.
		/// </remarks>
		/// <param name="cipherText">The encrypted text to decrypt.</param>
		/// <param name="algorithm">The <see cref="SymmetricAlgorithm"/> algorithm to use.</param>
		/// <returns>The clear text data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for decryption permission.</permission>
		public static byte[] Decrypt( byte[] cipherText, SymmetricAlgorithm algorithm )
		{
			// Verify parameters
			if( cipherText == null || cipherText.Length == 0 )
			{
				throw new ArgumentNullException( "cipherText" );
			}

			if( algorithm == null )
			{
				throw new ArgumentNullException( "algorithm" );
			}

			// Demand Permission
			new CryptographicPermission( CryptographicPermissionFlags.Decrypt ).Demand();

			// Create a MemoryStream that is going to accept the encrypted bytes
			MemoryStream ms = new MemoryStream();
			
			using( CryptoStream cs = new CryptoStream( ms, algorithm.CreateDecryptor(), CryptoStreamMode.Write) )
			{
				// Write the data and make it do the encryption 
				cs.Write( cipherText, 0, cipherText.Length );
				cs.Close(); 				
				return ms.ToArray(); 
			}
		}

		#region "Asymmetric decryption"

		/// <summary>
		/// Decrypt an hexadecimal string using an implementation of the <see cref="RSA"/> algorithm. 
		/// </summary>
		/// <remarks>
		/// Asymmentric encription is not intended to use for large input data.
		/// Use symmentric encryption for this scenarios.
		/// </remarks>
		/// <param name="cipherText">The cipher text decrypt encoded in hexadecimal.</param>
		/// <param name="parameters">The <see cref="RSAParameters"/> parameters to use.</param>
		/// <returns>The plaintext data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static string Decrypt( string cipherText, RSAParameters parameters )
		{
		    // Set oaep=true for Windows XP or better.
			return Utility.DefaultEncoding.GetString( Decrypt( Utility.FromHexString( cipherText ), parameters, false ) );
		}

		/// <summary>
		/// Decrypt a byte array using an implementation of the <see cref="RSA"/> algorithm. 
		/// </summary>
		/// <remarks>
		/// Asymmentric encription is not intended to use for large input data.
		/// Use symmentric encryption for this scenarios.
		/// </remarks>
		/// <param name="cipherText">The cipher text decrypt.</param>
		/// <param name="parameters">The <see cref="RSAParameters"/> parameters to use.</param>
		/// <param name="oaep">true to perform direct RSA encryption using OAEP 
		/// padding (only available on a computer running Microsoft Windows XP or 
		/// later); otherwise, false to use PKCS#1 v1.5 padding.</param>
		/// <returns>The plaintext data.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for decryption permission.</permission>
		public static byte[] Decrypt( byte[] cipherText, RSAParameters parameters, bool oaep )
		{
			// Verify parameters
			if( cipherText == null || cipherText.Length == 0 )
			{
				throw new ArgumentNullException( "cipherText" );
			}
			if( parameters.Modulus == null || parameters.Exponent == null )
			{
				throw new ArgumentNullException( "parameters.Modulus/parameters.Exponent" );
			}

			// Demand Permission
			new CryptographicPermission( CryptographicPermissionFlags.Decrypt ).Demand();

			RSACryptoServiceProvider rsa = RsaInstance;

			try
			{
				// Import the RSA Key information
				rsa.ImportParameters( parameters );

				// Check if we are able to encrpyt in one pass.
				int modulusSize = rsa.KeySize >> 3;
			
				if(cipherText.Length == modulusSize)
				{ 
					return rsa.Decrypt( cipherText, oaep ); 
				}
				else if( cipherText.Length % modulusSize != 0 )
				{
					throw new ArgumentOutOfRangeException( "cipherText", Resource.ResourceManager[ Resource.MessageKey.InvalidAsymmetricDataSize, modulusSize ] );
				}
				else
				{
					// The cipherText will need to be broken into segments 
					// of size rsa.KeySize/8
					// Each of these segments will be encrypted separately 
					// and will return encrypted data equal to the ModulusSize 
					// (with at least 11 bytes of padding).
				
					using( MemoryStream msin = new MemoryStream(cipherText) )
					using( MemoryStream msout = new MemoryStream(modulusSize) )
					{
						byte[] buffer = new byte[modulusSize];
						int bytesRead;
				
						do 
						{
							bytesRead = msin.Read(buffer, 0, modulusSize);
							if(bytesRead  > 0)
							{
								byte[] plain = rsa.Decrypt(buffer, oaep);
								msout.Write(plain, 0, plain.Length);
								Array.Clear(plain, 0, plain.Length);
							}
						} while (bytesRead > 0);

						return msout.ToArray();
					}
				}
			}
			finally
			{
				rsa.Clear();
			}
		}

		#endregion

		#endregion

		#region "Hashing methods"

		#region "ComputeHash"

		/// <summary>
		/// Computes the hash value. See <see cref="HashAlgorithm"/>.
		/// </summary>
		/// <param name="value">Data to be hashed.</param>
		/// <returns>The computed hash code in hexadecimal encoding.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static string ComputeHash( string value )
		{
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}

			// Instance of the default implementation of a hash algorithm.
			// This is SHA1 by default.
			HashAlgorithm algorithm = new SHA1Managed(); // HashAlgorithm.Create();

			try
			{
				return Utility.ToHexString( ComputeHash( Utility.DefaultEncoding.GetBytes( value ), algorithm ) );
			}
			finally
			{
				// Release resources
				algorithm.Clear();
			}
		}

		/// <summary>
		/// Computes hash for the <see cref="HashAlgorithm"/> specified. 
		/// </summary>
		/// <param name="value">Data to be hashed.</param>
		/// <param name="algorithm"><see cref="HashAlgorithm"/> to use.</param>
		/// <returns>The computed hash code in hexadecimal encoding.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static string ComputeHash( string value, HashAlgorithm algorithm )
		{
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}

			return Utility.ToHexString( ComputeHash( Utility.DefaultEncoding.GetBytes( value ), algorithm ) );
		}

		/// <summary>
		/// Computes hash for the <see cref="HashAlgorithm"/> specified. 
		/// </summary>
		/// <param name="value">Data to be hashed.</param>
		/// <param name="algorithm"><see cref="HashAlgorithm"/> to use.</param>
		/// <returns>The computed hash code.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static byte[] ComputeHash( byte[] value, HashAlgorithm algorithm )
		{
			// Validate Input
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}
			if( algorithm == null )
			{
				throw new ArgumentNullException( "algorithm" );
			}
			
			// Computes the hash.
			return algorithm.ComputeHash( value );			
		}

		#endregion

		#region "ComputeKeyedHash"

		/// <summary>
		/// Computes a Hash-based Message Authentication Code (HMAC) using the default implementation of a keyed hash algorithm.
		/// </summary>
		/// <remarks>
		/// The default implementation of <see cref="KeyedHashAlgorithm"/> is defined by the 
		/// cryptography configuration system. The keyed hash algorithms currently 
		/// supported are <see cref="HMACSHA1"/> and <see cref="MACTripleDES"/>.
		/// </remarks>
		/// <param name="value">Data to be hashed.</param>
		/// <param name="key">The key to be used in the hash algorithm.</param>
		/// <returns>The computed hash code in hexadecimal encoding.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static string ComputeKeyedHash( string value, byte[] key )
		{
			// Instance of the default implementation of a keyed hash algorithm.
			// This is HMACSHA1 by default.
			KeyedHashAlgorithm algorithm = new HMACSHA1(); // KeyedHashAlgorithm.Create();

			try
			{
				return ComputeKeyedHash( value, algorithm, key );
			}
			finally
			{
				algorithm.Clear();
			}
		}

		/// <summary>
		/// Computes a Hash-based Message Authentication Code (HMAC) using the specified algorithm.
		/// </summary>
		/// <param name="value">Data to be hashed.</param>
		/// <param name="algorithm"><see cref="KeyedHashAlgorithm"/> to use.</param>
		/// <param name="key">The key to be used in the hash algorithm.</param>
		/// <returns>The computed hash code in hexadecimal encoding.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static string ComputeKeyedHash( string value, KeyedHashAlgorithm algorithm, byte[] key )
		{
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}

			return Utility.ToHexString( ComputeKeyedHash( Utility.DefaultEncoding.GetBytes( value ), algorithm, key ) );
		}

		/// <summary>
		/// Computes a Hash-based Message Authentication Code (HMAC) using the specified algorithm.
		/// </summary>
		/// <param name="value">Data to be hashed.</param>
		/// <param name="algorithm"><see cref="KeyedHashAlgorithm"/> to use.</param>
		/// <returns>The computed hash code.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static byte[] ComputeKeyedHash( byte[] value, KeyedHashAlgorithm algorithm )
		{
			return ComputeKeyedHash( value, algorithm, algorithm.Key );
		}

		/// <summary>
		/// Computes a Hash-based Message Authentication Code (HMAC) using the specified algorithm.
		/// </summary>
		/// <param name="value">Data to be hashed.</param>
		/// <param name="algorithm"><see cref="KeyedHashAlgorithm"/> to use.</param>
		/// <param name="key">The key to be used in the hash algorithm.</param>
		/// <returns>The computed hash code.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static byte[] ComputeKeyedHash( byte[] value, KeyedHashAlgorithm algorithm, byte[] key )
		{
			// Validate Input
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}
			if( algorithm == null )
			{
				throw new ArgumentNullException( "value" );
			}
			if( key == null || key.Length == 0 )
			{
				throw new ArgumentNullException( "key" );
			}

			// Check if the key lenght is appropiate for this algorithm
			int validKeySize = algorithm.Key.Length;

			if( key.Length != validKeySize )
			{
				// Adjust the key size adding new material
				// We use the original key as a seed to derive a new key
				// with the appropiate key size.
				PKCS1MaskGenerationMethod pm = new PKCS1MaskGenerationMethod();
				key = pm.GenerateMask( key, validKeySize );
			}
			// Set the key value.
			algorithm.Key = key;

			// Computes the keyed hash.
			return algorithm.ComputeHash( value );
		}

		#endregion 

		#region "ComputeSaltedHash"

		/// <summary>
		/// Computes a salted hash for data validation.
		/// </summary>
		/// <param name="value">Data to be hashed.</param>
		/// <returns>Returns the salt and the hashed data in hexadecimal encoding appended at the end of the array
		/// The total array lenght will be the sum of the hash (varies with the algorithm used) and the salt (same length as the hash).
		/// </returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static string ComputeSaltedHash( string value )
		{
			// Instance of the default implementation of a hash algorithm.
			// This is SHA1 by default.
			HashAlgorithm algorithm = new SHA1Managed(); // HashAlgorithm.Create();

			try
			{
				return ComputeSaltedHash( value, algorithm );
			}
			finally
			{
				// Scrub data maintained by the crypto class
				algorithm.Clear();
			}
		}

		/// <summary>
		/// Computes a salted hash for data validation.
		/// </summary>
		/// <param name="value">Data to be hashed.</param>
		/// <param name="algorithm"><see cref="HashAlgorithm"/> to use.</param>
		/// <returns>Returns the salt and the hashed data in hexadecimal encoding appended at the end of the array
		/// The total array lenght will be the sum of the hash (varies with the algorithm used) and the salt (same length as the hash).
		/// </returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static string ComputeSaltedHash( string value, HashAlgorithm algorithm )
		{
			// Validate Input
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}

			return Utility.ToHexString( ComputeSaltedHash( Utility.DefaultEncoding.GetBytes( value ), algorithm ) );
		}

		/// <summary>
		/// Computes a salted hash for data validation.
		/// </summary>
		/// <param name="value">Data to be hashed.</param>
		/// <param name="algorithm"><see cref="HashAlgorithm"/> to use.</param>
		/// <returns>Returns the salt and the hashed data appended at the end of the array.
		/// The total array lenght will be the sum of the hash (varies with the algorithm used) and the salt (same length as the hash).
		/// </returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static byte[] ComputeSaltedHash( byte[] value, HashAlgorithm algorithm )
		{
			// Validate Input
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}
			if( algorithm == null )
			{
				throw new ArgumentNullException( "algorithm" );
			}

			// Gets the size of the computed hash code in bytes.
			int hashSize = ( algorithm.HashSize ) >> 3; // divide by 8

			// Creates the salt value
			byte[] salt = ComputeRandomBytes( hashSize );

			//Returns the salt + hash
			return Utility.JoinArrays( salt, ComputeHash( Utility.JoinArrays( salt, value ), algorithm ) );
		}
		#endregion

		#region "VerifySaltedHash"

		/// <summary>
		/// Validates the salted hash created with the <see cref="ComputeSaltedHash(string)"/> method.
		/// </summary>
		/// <param name="value">Data to be hashed.</param>
		/// <param name="saltedhash">The salted hash in hexadecimal encoding.</param>
		/// <returns>True if the data and the salted hash are equals; false othrewise.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static bool VerifySaltedHash( string value, string saltedhash )
		{
			// Instance of the default implementation of a hash algorithm.
			// This is SHA1 by default.
			HashAlgorithm algorithm = new SHA1Managed(); // HashAlgorithm.Create();

			try
			{
				return VerifySaltedHash( value, saltedhash, algorithm );
			}
			finally
			{
				// Scrub data maintained by the crypto class
				algorithm.Clear();
			}
		}

		/// <summary>
		/// Validates the salted hash created with the <see cref="ComputeSaltedHash(string)"/> method.
		/// </summary>
		/// <param name="value">Data to be hashed.</param>
		/// <param name="saltedhash">The salted hash in hexadecimal encoding.</param>
		/// <param name="algorithm"><see cref="HashAlgorithm"/> to use.</param>
		/// <returns>True if the data and the salted hash are equals; false othrewise.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static bool VerifySaltedHash( string value, string saltedhash, HashAlgorithm algorithm )
		{
			// Validate Input
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}
			if( saltedhash == null )
			{
				throw new ArgumentNullException( "saltedhash" );
			}

			return VerifySaltedHash( Utility.DefaultEncoding.GetBytes( value ), Utility.FromHexString( saltedhash ), algorithm ); 
		}

		/// <summary>
		/// Validates the salted hash created with the <see cref="ComputeSaltedHash(string)"/> method.
		/// </summary>
		/// <param name="value">Data to be hashed.</param>
		/// <param name="saltedhash">The salted hash.</param>
		/// <param name="algorithm"><see cref="HashAlgorithm"/> to use.</param>
		/// <returns>True if the data and the salted hash are equals; false othrewise.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static bool VerifySaltedHash( byte[] value, byte[] saltedhash, HashAlgorithm algorithm )
		{
			// Validate Input
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}
			if( algorithm == null )
			{
				throw new ArgumentNullException( "algorithm" );
			}
			if( saltedhash == null )
			{
				throw new ArgumentNullException( "saltedhash" );
			}

			// Gets the size of the computed hash code in bytes.
			int hashSize = ( algorithm.HashSize ) >> 3; // divide by 8

			// Extracts the salt from the saltedhash
			SplitArray saltAndHash = Utility.SplitArrays( saltedhash, hashSize );

			// Compare the arrays and return the result
			return Utility.CompareArrays( saltAndHash.SecondArray(), ComputeHash( Utility.JoinArrays( saltAndHash.FirstArray(), value ), algorithm ) );
		}
		#endregion

		#endregion

		#region "Signing methods"

		/// <summary>
		/// Creates the signature for the specified data.
		/// </summary>
		/// <param name="value">The data to be signed.</param>
		/// <returns>The digital signature for the value parameter in base64 encoding.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for sign permission.</permission>
		public static string Sign( string value )
		{
			// Creates the default alg. (RSA)
			AsymmetricAlgorithm algorithm =  RsaInstance;

			try
			{
				return Sign( value, algorithm );
			}
			finally
			{
				// Scrub data maintained by the crypto class
				algorithm.Clear();
			}
		}

		/// <summary>
		/// Creates the signature for the specified data.
		/// </summary>
		/// <param name="value">The data to be signed.</param>
		/// <param name="algorithm">The <see cref="AsymmetricAlgorithm"/> to use for signing the data.</param>
		/// <returns>The digital signature for the value parameter in base64 encoding.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for sign permission.</permission>
		public static string Sign( string value, AsymmetricAlgorithm algorithm )
		{
			// Use the default implementation of a hash algorithm.
			// This is SHA1 by default.
			HashAlgorithm hash = new SHA1Managed(); // HashAlgorithm.Create();
			
			try
			{
				return Convert.ToBase64String( Sign( value, algorithm, hash ) );
			}
			finally
			{
				// Scrub data maintained by the crypto class
				hash.Clear();
			}
		}

		/// <summary>
		/// Creates the signature for the specified data.
		/// </summary>
		/// <param name="value">The data to be signed.</param>
		/// <param name="algorithm">The <see cref="AsymmetricAlgorithm"/> to use for signing the data.</param>
		/// <param name="hash">The hash algorithm to use to create the signature.</param>
		/// <returns>The digital signature for the value parameter.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for sign permission.</permission>
		public static byte[] Sign( string value, AsymmetricAlgorithm algorithm, HashAlgorithm hash )
		{
			// Parameter checks 
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}
			if( algorithm == null )
			{
				throw new ArgumentNullException( "algorithm" );
			}
			if( hash == null )
			{
				throw new ArgumentNullException( "hash" );
			}

			// Demand Permission
			new CryptographicPermission( CryptographicPermissionFlags.Sign ).Demand();

			// Turn the input string into a byte array.  
			byte[] userData = Utility.DefaultEncoding.GetBytes( value );

			try
			{
				AsymmetricSignatureFormatter asf = GetAsymmetricFormatter( algorithm );
				asf.SetHashAlgorithm( hash.ToString() );
				return asf.CreateSignature( ComputeHash( userData, hash ) ) ;
			}
			finally
			{
				// Erase bytes
				Array.Clear( userData, 0, userData.Length );
			}
		}

		/// <summary>
		/// Verifies the signature created with <see cref="Sign(string)"/>.
		/// </summary>
		/// <param name="value">The data to be verified.</param>
		/// <param name="signature">The signature to be verified in base64 encoding.</param>
		/// <returns>true if the signature is valid for the hash; otherwise, false.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for sign permission.</permission>
		public static bool VerifySignature( string value, string signature )
		{
			// Creates the default alg. (RSA)
			AsymmetricAlgorithm algorithm =  RsaInstance;

			try
			{
				return VerifySignature( value, signature, algorithm );
			}
			finally
			{
				// Scrub data maintained by the crypto class
				algorithm.Clear();
			}
		}

		/// <summary>
		/// Verifies the signature created with <see cref="Sign(string)"/>.
		/// </summary>
		/// <param name="value">The data to be verified.</param>
		/// <param name="signature">The signature to be verified in base64 encoding.</param>
		/// <param name="algorithm">The <see cref="AsymmetricAlgorithm"/> to use for signing the data.</param>
		/// <returns>true if the signature is valid for the hash; otherwise, false.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for sign permission.</permission>
		public static bool VerifySignature( string value, string signature, AsymmetricAlgorithm algorithm )
		{
			// Parameters validation
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}
			if( !Utility.IsBase64Encoding( signature ) )
			{
				throw new ArgumentException( Resource.ResourceManager[ Resource.MessageKey.Base64EncodingException, signature ] );
			}

			// Use the default implementation of a hash algorithm.
			// This is SHA1 by default.
			HashAlgorithm hash = new SHA1Managed(); // HashAlgorithm.Create();

			try
			{
				return VerifySignature( Utility.DefaultEncoding.GetBytes( value ), Convert.FromBase64String( signature ), algorithm, hash );
			}
			finally
			{
				// Scrub data maintained by the crypto class
				hash.Clear();
			}
		}

		/// <summary>
		/// Verifies the signature created with <see cref="Sign(string)"/>.
		/// </summary>
		/// <param name="value">The data to be verified.</param>
		/// <param name="signature">The signature to be verified.</param>
		/// <param name="algorithm">The <see cref="AsymmetricAlgorithm"/> to use for signing the data.</param>
		/// <param name="hash">The hash algorithm to use to verify the signature.</param>
		/// <returns>true if the signature is valid for the hash; otherwise, false.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <permission cref="CryptographicPermission">Demand for sign permission.</permission>
		public static bool VerifySignature( byte[] value, byte[] signature, AsymmetricAlgorithm algorithm,  HashAlgorithm hash )
		{
			// Demand Permission
			new CryptographicPermission( CryptographicPermissionFlags.Sign ).Demand();

			// Validate Input
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}
			if( signature == null )
			{
				throw new ArgumentNullException( "signature" );
			}
			if( algorithm == null )
			{
				throw new ArgumentNullException( "algorithm" );
			}
			if( hash == null )
			{
				throw new ArgumentNullException( "hash" );
			}

			AsymmetricSignatureDeformatter asd = GetAsymmetricDeformatter( algorithm );
			asd.SetHashAlgorithm( hash.ToString() );
			return asd.VerifySignature( ComputeHash( value, hash ) , signature ) ;
		}

		#endregion

		#region "RNG methods"

		/// <summary>
		/// Fills an array of bytes with a cryptographically strong random sequence of values.
		/// </summary>
		/// <param name="randomBytes">Determines how many cryptographically strong random bytes are produced.</param>
		/// <returns>The array with the specified cryptographically strong random bytes.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static byte[] ComputeRandomBytes( int randomBytes )
		{
			// Validate input
			if( randomBytes <= 0 )
			{
				throw new ArgumentOutOfRangeException( "randomBytes" );
			}

			byte[] data = new byte[ randomBytes ];

			_rng.GetBytes( data );
			
			return (byte[])data.Clone();
		}

		#endregion

		#endregion

		#region "Private methods"

		// Gets the AsymmetricSignatureFormatter based on the AsymmetricAlgorithm passed.
		private static AsymmetricSignatureFormatter GetAsymmetricFormatter( AsymmetricAlgorithm key )
		{			
			AsymmetricSignatureFormatter asf;

			if( key is RSA )
			{
				asf = new RSAPKCS1SignatureFormatter( key );
			}
			else if( key is DSA )
			{
				asf = new DSASignatureFormatter( key );
			}
			else
			{
				// Didn't found any known formatter.
				throw new CryptographicUnexpectedOperationException( Resource.ResourceManager[ Resource.MessageKey.UnknownAsymmetricFormatter ] );
			}

			return asf;
		}

		// Gets the AsymmetricSignatureDeformatter based on the AsymmetricAlgorithm passed.
		private static AsymmetricSignatureDeformatter GetAsymmetricDeformatter( AsymmetricAlgorithm key )
		{
			AsymmetricSignatureDeformatter asd;

			if( key is RSA )
			{
				asd = new RSAPKCS1SignatureDeformatter( key );
			}
			else if( key is DSA )
			{
				asd = new DSASignatureDeformatter( key );
			}
			else
			{
				// Didn't found any known formatter.
				throw new CryptographicUnexpectedOperationException( Resource.ResourceManager[ Resource.MessageKey.UnknownAsymmetricDeformatter ]);
			}

			return asd;
		}

		#endregion
	}

}
