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
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using System.Security.Permissions;

namespace NCrypto.Security.Cryptography
{
	#region "SplitArray Struct"

	/// <summary>
	/// SplitArray struct for array splitting operations
	/// </summary>
	public struct SplitArray
	{
		#region "Private fields and initializers"

		private byte[] _firstArray;
		private byte[] _secondArray;

		/// <summary>
		/// Default initializer.
		/// </summary>
		public SplitArray( byte[] first, byte[] second )
		{
			_firstArray = (byte[])first.Clone();
			_secondArray = (byte[])second.Clone();
		}
		#endregion

		#region "Public properties"
		/// <summary>
		/// First byte array.
		/// </summary>
		public byte[] FirstArray()
		{
			return _firstArray;
		}

		/// <summary>
		/// Second byte array.
		/// </summary>
		public byte[] SecondArray()
		{
			return _secondArray;
		}
		#endregion

		#region "Equals override"
		/// <summary>
		/// The Equals method determines whether the specified System.Object is equal to the current System.Object.
		/// </summary>
		public override bool Equals (object obj)
		{
			if(obj.GetType() != typeof(SplitArray))
			{
				return false;
			}
                
			SplitArray value = (SplitArray)obj;   

			return Utility.CompareArrays( this.FirstArray(), value.FirstArray() ) && 
				   Utility.CompareArrays( this.SecondArray(), value.SecondArray() );	
		}

		/// <summary>
		/// Hashcode implementation.
		/// </summary>
		public override int GetHashCode()
		{
			return this.GetHashCode();
		}

		/// <summary>
		/// equality operator
		/// </summary>
		public static bool operator== (SplitArray sp1, SplitArray sp2)
		{
			return Utility.CompareArrays( sp1.FirstArray(), sp2.FirstArray() ) && 
				   Utility.CompareArrays( sp1.SecondArray(), sp2.SecondArray() );	
		}

		/// <summary>
		/// inequality operator
		/// </summary>
		public static bool operator!= (SplitArray sp1, SplitArray sp2)
		{
			return !(sp1 == sp2);
		}

		#endregion
	}
	#endregion

	#region "Utility"

	/// <summary>
	/// Helper common methods.
	/// </summary>
	public sealed class Utility
	{
		#region "Private Fields & Constructors"

		// Precompiled hexadecimal regular expression
		private static readonly Regex ExpHexa = new Regex(@"^[A-Fa-f0-9]{2,}$", RegexOptions.Compiled);
		// Precompiled base64 regular expression
		private static readonly Regex ExpBase64 = new Regex(@"^[a-zA-Z0-9+/=]{4,}$", RegexOptions.Compiled);

		// Size of buffer for stream operations
		private const int BufferSize = 4096;

		// Since this class provides only static methods, make the default constructor private to prevent 
		// instances from being created with "new Utility()".
		private Utility() {}

		#endregion

		#region "Public Fields & Constants"

		/// <summary>
		/// Default encoding in <see cref="Encoding.UTF8"/> format.
		/// </summary>
		public static Encoding DefaultEncoding
		{
			get{ return Encoding.UTF8; }	
		}
		#endregion

		#region "Public methods"

		#region "Stream methods"

		/// <summary>
		/// Helper function for stream data transference.
		/// </summary>
		/// <remarks>
		/// Transfers 4KB blocks between input and output streams.
		/// It's consumer responsability to open and close both streams.
		/// </remarks>
		/// <param name="input">Input stream.</param>
		/// <param name="output">Output stream.</param>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static void TransferStreams(Stream input, Stream output)
		{
			// Validate parameters
			if( input == null )
			{
				throw new ArgumentNullException( "input" );
			}

			if( output == null )
			{
				throw new ArgumentNullException( "output" );
			}

			byte[] buffer = new byte[BufferSize];
			int bytesRead;
			
			if(input.CanSeek) input.Position = 0;
			
			do 
			{
				bytesRead = input.Read(buffer, 0, BufferSize);
				output.Write(buffer,0,bytesRead);
			} while (bytesRead > 0);

			output.Flush();
			
			if(output.CanSeek) output.Position = 0;
		}

		#endregion

		#region "Encoding methods"

		/// <summary>
		/// Converts the value of an array of 8-bit unsigned integers to its equivalent 
		/// <see cref="String"/> representation consisting of base 16 digits.
		/// </summary>
		/// <param name="inArray">An array of 8-bit unsigned integers.</param>
		/// <returns>The <see cref="String"/> representation, in base 16, of the contents of inArray.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		public static string ToHexString(byte[] inArray) 
		{
			if( inArray == null )
			{
				throw new ArgumentNullException( "inArray" );
			}

			return BitConverter.ToString( inArray ).Replace( "-", string.Empty );
		}

		/// <summary>
		/// Converts the specified <see cref="String"/> representation of a value 
		/// consisting of hexadecimal digits to an equivalent array of 8-bit unsigned integers.
		/// </summary>
		/// <param name="value">A <see cref="String"/></param>
		/// <returns>An array of 8-bit unsigned integers equivalent to s.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <exception cref="ArgumentOutOfRangeException">The lenght of the input data is not even.</exception>
		public static byte[] FromHexString( string value )
		{
			// Parameter validation
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}
			if( !IsHexEncoding( value ) )
			{
				throw new ArgumentException( Resource.ResourceManager[ Resource.MessageKey.HexaEncodingException, value ] );
			}

			byte[] result = new byte[ value.Length >> 1 ]; //(>>1 = Lenght * 2)

			for(int index = 0; index < result.Length; index++)
			{
				result[ index ] = Convert.ToByte( "0x" + value.Substring( index << 1, 2 ), 16 );
			}

			return result;
		}

		/// <summary>
		/// Test if the passed data is in hexadecimal encoding.
		/// </summary>
		/// <param name="value"></param>
		/// <returns></returns>
		public static bool IsHexEncoding( string value )
		{
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}

			return ( ExpHexa.IsMatch( value ) && 
				   ( value.Length % 2 == 0 ) ); 
		}

		/// <summary>
		/// Test if the passed data is in base64 encoding.
		/// </summary>
		/// <param name="value"></param>
		/// <returns></returns>
		public static bool IsBase64Encoding( string value )
		{
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}

			return ExpBase64.IsMatch( value );
		}

		#endregion

		#region "Arrays methods"

		/// <summary>
		/// Joins two arrays into one.
		/// </summary>
		/// <param name="value">The <see cref="SplitArray"/> containing the two arrays to join</param>
		/// <returns>The union of the two arrays.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <exception cref="ArgumentOutOfRangeException">The lenght of the two arrays is gretar thant the <see cref="int.MaxValue"/>.</exception>
		public static byte[] JoinArrays( SplitArray value )
		{
			return JoinArrays( value.FirstArray(), value.SecondArray() );
		}

		/// <summary>
		/// Joins two arrays into one.
		/// </summary>
		/// <param name="first">The first array to join.</param>
		/// <param name="second">The second array to join.</param>
		/// <returns>The sum of the two arrays.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <exception cref="ArgumentOutOfRangeException">The lenght of the two arrays is gretar thant the <see cref="int.MaxValue"/>.</exception>
		public static byte[] JoinArrays( byte[] first, byte[] second )
		{
			// Verify parameters
			if( first == null )
			{
				throw new ArgumentNullException( "first" );
			}
			if( second == null )
			{
				throw new ArgumentNullException( "second" );
			}

			// Verify total length
			if( (int.MaxValue - first.Length) < second.Length )
			{
				throw new OverflowException();
			}

			byte[] total = new byte[ first.Length + second.Length ];
			
			Buffer.BlockCopy( first, 0, total, 0, first.Length );
			Buffer.BlockCopy( second, 0, total, first.Length, second.Length);

			return (byte[])total.Clone();
		}

		/// <summary>
		/// Split an array in two.
		/// </summary>
		/// <param name="value">The array to be splitted.</param>
		/// <param name="offset">The pointcut index number.</param>
		/// <returns>A <see cref="SplitArray"/> struct with the two arrays obtained from the value parameter.</returns>
		/// <exception cref="ArgumentNullException">The specified parameter is a null reference (Nothing in Visual Basic).</exception>
		/// <exception cref="ArgumentOutOfRangeException">The offset is out of range.</exception>
		public static SplitArray SplitArrays( byte[] value, int offset )
		{
			// Verify parameters
			if( value == null )
			{
				throw new ArgumentNullException( "value" );
			}	
			if( offset <= 0 || offset >= value.Length )
			{
				throw new ArgumentOutOfRangeException( "offset" );
			}

			byte[] first = new byte[ offset ];
			byte[] second = new byte[ value.Length - offset ];
			
			Buffer.BlockCopy( value, 0, first, 0, first.Length );		
			Buffer.BlockCopy( value, first.Length, second, 0, second.Length );			
			
			return new SplitArray( first, second );			 
		}

		/// <summary>
		/// Compares two byte arrays.
		/// </summary>
		/// <param name="value">The <see cref="SplitArray"/> containing the two arrays to compare.</param>
		/// <returns>True if the arrays are equals; false otherwise.</returns>
		public static bool CompareArrays( SplitArray value )
		{
			return CompareArrays( value.FirstArray(), value.SecondArray() );
		}

		/// <summary>
		/// Compares two byte arrays.
		/// </summary>
		/// <param name="a">The first byte array to compare.</param>
		/// <param name="b">The second byte array to compare.</param>
		/// <returns>True if the arrays are equals; false otherwise.</returns>
		public static bool CompareArrays( byte[] a, byte[] b )
		{
			// Validate length
			if(a == null || b == null || a.Length != b.Length)
			{
				return false;
			}

			int index;
			
			for( index = 0; index < a.Length; index++ )
			{				
				if( a[index] != b[index] )
				{
					break;
				}
			}				

			return ( index == a.Length );
		}

		#endregion

		#endregion
	}
	#endregion
}
