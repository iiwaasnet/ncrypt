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

using NCrypto.Security.Cryptography;

namespace TestNCrypto
{
	/// <summary>
	/// Symmetric Algorithms
	/// </summary>
	public enum SymmetricAlgorithms
	{
		/// <summary>
		/// Default Symmetric Algorithm (Rijndael) 
		/// </summary>
		Default,
		/// <summary>
		/// Rijndael symmetric algorithm.
		/// </summary>
		Rijndael,
		/// <summary>
		/// Data Encryption Standard Algorithm.
		/// </summary>
		DES,
		/// <summary>
		/// Triple Data Encryption Standard Algorithm.
		/// </summary>
		TripleDES,
		/// <summary>
		/// RC2 Block cypher algorithm.
		/// </summary>
		RC2
	}

	/// <summary>
	/// Asymmetric Algorithms
	/// </summary>
	public enum AsymmetricAlgorithms
	{
		/// <summary>
		/// Default Asymmetric Algorithm (RSA)
		/// </summary>
		Default,
		///<summary>
		/// RSA Algorithm
		///</summary>
		RSA,
		/// <summary>
		/// DSA Algorithm 
		/// </summary>
		DSA
	}

	/// <summary>
	/// Hash Algorithms
	/// </summary>
	public enum HashAlgorithms
	{
		/// <summary>
		/// Default Hash Algorithm (SHA1)
		/// </summary>
		Default,
		///<summary>
		///MD5 Hashing algorithm.(Default=SHA1)
		///</summary>
		MD5,
		/// <summary>
		/// SHA1 Hashing algorithm.
		/// </summary>
		SHA1,
		/// <summary>
		/// SHA256 Hashing algorithm.
		/// </summary>
		SHA256,
		/// <summary>
		/// SHA384 Hashing algorithm.
		/// </summary>
		SHA384,
		/// <summary>
		/// SHA512 Hashing algorithm.
		/// </summary>
		SHA512
	}

	/// <summary>
	/// Keyed Hash Algorithms
	/// </summary>
	public enum KeyedHashAlgorithms
	{
		/// <summary>
		/// Default Keyed Hash Algorithm (HMACSHA1)
		/// </summary>
		Default,
		///<summary>
		///HMAC Keyed hashed algorithm.(Default=HmacSha1)
		///</summary>
		HMACSHA1,
		/// <summary>
		///MACTripleDES Keyed hashed algorithm.(Default=HmacSha1)
		/// </summary>
		MACTripleDES
	}
}
