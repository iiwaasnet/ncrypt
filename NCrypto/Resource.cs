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
using System.Resources;
using System.Reflection; 
using System.IO;
using System.Globalization;

namespace NCrypto.Security.Cryptography
{
	/// <summary>
	/// Helper class used to manage application Resources
	/// </summary>
	internal sealed class Resource
	{
		#region "MessageKey enum"

		/// <summary>
		/// Enumeration of all messages for strong typing
		/// </summary>
		internal enum MessageKey 
		{
			/// <summary>Message key for resource retrieval.</summary>
			ProtectDataException,
			/// <summary>Message key for resource retrieval.</summary>
			UnprotectDataException,
			/// <summary>Message key for resource retrieval.</summary>
			OutOfMemoryException,
			/// <summary>Message key for resource retrieval.</summary>
			ProtectMemoryException,
			/// <summary>Message key for resource retrieval.</summary>
			UnprotectMemoryException,
			/// <summary>Message key for resource retrieval.</summary>
			CredUIReturn,
			/// <summary>Message key for resource retrieval.</summary>
			InvalidMemoryBlockSize,
			/// <summary>Message key for resource retrieval.</summary>
			UnknownAsymmetricFormatter,
			/// <summary>Message key for resource retrieval.</summary>
			UnknownAsymmetricDeformatter,
			/// <summary>Message key for resource retrieval.</summary>
			HexaEncodingException,
			/// <summary>Message key for resource retrieval.</summary>
			Base64EncodingException,
			/// <summary>Message key for resource retrieval.</summary>
			PlatformNotSupportedException,
			/// <summary>Message key for resource retrieval.</summary>
			InvalidDataProtectionScope,
			/// <summary>Message key for resource retrieval.</summary>
			NullContextException,
			/// <summary>Message key for resource retrieval.</summary>
			LogonUserException,
			/// <summary>Message key for resource retrieval.</summary>
			CryptographicPermissionArgumentException,
			/// <summary>Message key for resource retrieval.</summary>
			InvalidPermissionState,
			/// <summary>Message key for resource retrieval.</summary>
			InvalidAsymmetricDataSize,
			/// <summary>Message key for resource retrieval.</summary>
			ReflectionTypeLoadException
		}

		#endregion

		#region "Static part"

		/// <summary>
		/// Resource singleton instance
		/// </summary>
		static Resource InternalResource = new Resource();

		/// <summary>
		/// Gets a resource manager for the assembly resource file
		/// </summary>
		public static Resource ResourceManager
		{
			get{ return InternalResource; }
		}

		#endregion
		
		#region "Private members"

		/// <summary>
		/// String for name of resx file used to store message strings.
		/// </summary>
		private const string ResourceFileName = ".Messages";

		/// <summary>
		/// The resource manager instance
		/// </summary>
		private ResourceManager _rm = null;

		#endregion

		#region "Constructors"

		/// <summary>
		/// Default constructor
		/// </summary>
		private Resource()
		{
			_rm = new ResourceManager(this.GetType().Namespace + ResourceFileName, Assembly.GetExecutingAssembly());
		}

		#endregion

		#region "Public properties"

		/// <summary>
		/// Gets the message with the specified MessageKey enum key from the assembly resource file
		/// </summary>
		public string this [ MessageKey key ]
		{
			get
			{
				string keyValue = key.ToString();
				return _rm.GetString( keyValue, CultureInfo.CurrentUICulture );
			}
		}

		/// <summary>
		/// Gets the message with the specified MessageKey enum key from the assembly resource file
		/// </summary>
		public string this [ MessageKey key, params object[] parameters ]
		{
			get
			{
				return this.FormatMessage( key, parameters );
			}
		}

		#endregion

		#region "Private members"

		/// <summary>
		/// Formats a message stored in the assembly resource file
		/// </summary>
		/// <param name="key"><see cref="MessageKey"/> enumeration key</param>
		/// <param name="format">format arguments</param>
		/// <returns>a formated string</returns>
		private string FormatMessage( MessageKey key, params object[] format )
		{
			return String.Format( CultureInfo.CurrentUICulture, this[key], format );  
		}

		#endregion
	}
}