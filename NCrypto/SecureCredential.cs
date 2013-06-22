using System;
using System.Runtime.InteropServices;

namespace NCrypto.Security.Cryptography
{
	/// <summary>
	/// Summary description for SecureCredential.
	/// </summary>
	public class SecureCredential : IDisposable
	{
		#region Private Fields

		private string _user;
		private SecureString _password;
		private string _domain;

		private bool m_disposed;

		#endregion

		#region Constructors & Finalizers

		/// <summary>
		/// Constructor
		/// </summary>
		public SecureCredential( string user, SecureString password ) : this( user, password, Environment.UserDomainName )
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		public SecureCredential( string user, SecureString password, string domain )
		{
			_user = user;
			_password = password.Copy();
			_password.MakeReadOnly();
			_domain = domain;
		}

		/// <summary>
		/// Constructor
		/// </summary>
		[CLSCompliant(false)]
		unsafe public SecureCredential( string user,  char* password, int length ) : this( user, password, length, Environment.UserDomainName )
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		[CLSCompliant(false)]
		unsafe public SecureCredential( string user, char* password, int length, string domain )
		{
			_user = user;
			_password = new SecureString( password, length );
			_password.MakeReadOnly();
			_domain = domain;
		}

		/// <summary>
		/// Finalizer
		/// </summary>
		~SecureCredential()
		{
			Dispose(false);
			return;
		}

		#endregion

		#region Public Members

		/// <summary>
		/// User Id
		/// </summary>
		public string User
		{
			get{ return _user; }
		}

		/// <summary>
		/// Password
		/// </summary>
		public SecureString Password
		{
			get{ return _password; }
		}

		/// <summary>
		/// Domain name
		/// </summary>
		public string Domain
		{
			get{ return _domain; }
		}

		#endregion

		#region IDisposable Members

		/// <summary>
		/// 
		/// </summary>
		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this); 
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="disposing"></param>
		public void Dispose(bool disposing)
		{
			if( !m_disposed )
			{
				_password.Dispose();
				m_disposed = true; 
			} 
		}

		#endregion
	}
}
