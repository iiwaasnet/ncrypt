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
using System.Drawing;
using System.Collections;
using System.ComponentModel;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Runtime.InteropServices;

using NCrypto.Security.Cryptography;

namespace TestNCrypto
{
	/// <summary>
	/// Summary description for CryptoTestHarness.
	/// </summary>
	public class CryptoTestHarness : System.Windows.Forms.Form
	{
		private System.Windows.Forms.GroupBox groupBox1;
		private System.Windows.Forms.GroupBox gbResult;
		private System.Windows.Forms.Label label3;
		private System.Windows.Forms.Label label6;
		private System.Windows.Forms.GroupBox MethodsDetails;
		private System.Windows.Forms.Label label11;
		private System.Windows.Forms.Button CloseForm;
		private System.Windows.Forms.Button Execute;
		private System.Windows.Forms.TextBox InputData;
		private System.Windows.Forms.TextBox OutputData;
		private System.Windows.Forms.ComboBox Algorithm;
		private System.Windows.Forms.ComboBox Method;
		private System.Windows.Forms.Button button1;
		private System.Windows.Forms.TextBox Password;
		private System.Windows.Forms.Button button2;
		private System.Windows.Forms.Button LogonUser;
		private System.Windows.Forms.CheckBox chkLocalMachine;
		/// <summary>
		/// Required designer variable.
		/// </summary>
		private System.ComponentModel.Container components = null;

		public CryptoTestHarness()
		{
			//
			// Required for Windows Form Designer support
			//
			InitializeComponent();

			//
			// TODO: Add any constructor code after InitializeComponent call
			//
		}

		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		protected override void Dispose( bool disposing )
		{
			if( disposing )
			{
				if (components != null) 
				{
					components.Dispose();
				}
			}
			base.Dispose( disposing );
		}

		#region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent()
		{
			this.groupBox1 = new System.Windows.Forms.GroupBox();
			this.InputData = new System.Windows.Forms.TextBox();
			this.gbResult = new System.Windows.Forms.GroupBox();
			this.OutputData = new System.Windows.Forms.TextBox();
			this.Password = new System.Windows.Forms.TextBox();
			this.label3 = new System.Windows.Forms.Label();
			this.Algorithm = new System.Windows.Forms.ComboBox();
			this.label6 = new System.Windows.Forms.Label();
			this.MethodsDetails = new System.Windows.Forms.GroupBox();
			this.Method = new System.Windows.Forms.ComboBox();
			this.label11 = new System.Windows.Forms.Label();
			this.LogonUser = new System.Windows.Forms.Button();
			this.chkLocalMachine = new System.Windows.Forms.CheckBox();
			this.CloseForm = new System.Windows.Forms.Button();
			this.Execute = new System.Windows.Forms.Button();
			this.button1 = new System.Windows.Forms.Button();
			this.button2 = new System.Windows.Forms.Button();
			this.groupBox1.SuspendLayout();
			this.gbResult.SuspendLayout();
			this.MethodsDetails.SuspendLayout();
			this.SuspendLayout();
			// 
			// groupBox1
			// 
			this.groupBox1.Controls.Add(this.InputData);
			this.groupBox1.FlatStyle = System.Windows.Forms.FlatStyle.System;
			this.groupBox1.Location = new System.Drawing.Point(16, 164);
			this.groupBox1.Name = "groupBox1";
			this.groupBox1.Size = new System.Drawing.Size(231, 156);
			this.groupBox1.TabIndex = 12;
			this.groupBox1.TabStop = false;
			this.groupBox1.Text = "Input Data";
			// 
			// InputData
			// 
			this.InputData.Location = new System.Drawing.Point(12, 24);
			this.InputData.Multiline = true;
			this.InputData.Name = "InputData";
			this.InputData.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
			this.InputData.Size = new System.Drawing.Size(208, 120);
			this.InputData.TabIndex = 0;
			this.InputData.Text = "Test plain text data.";
			// 
			// gbResult
			// 
			this.gbResult.Controls.Add(this.OutputData);
			this.gbResult.FlatStyle = System.Windows.Forms.FlatStyle.System;
			this.gbResult.Location = new System.Drawing.Point(256, 8);
			this.gbResult.Name = "gbResult";
			this.gbResult.Size = new System.Drawing.Size(424, 312);
			this.gbResult.TabIndex = 11;
			this.gbResult.TabStop = false;
			this.gbResult.Text = "Output Data";
			// 
			// OutputData
			// 
			this.OutputData.Location = new System.Drawing.Point(12, 24);
			this.OutputData.Multiline = true;
			this.OutputData.Name = "OutputData";
			this.OutputData.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
			this.OutputData.Size = new System.Drawing.Size(400, 276);
			this.OutputData.TabIndex = 0;
			this.OutputData.Text = "";
			// 
			// Password
			// 
			this.Password.Location = new System.Drawing.Point(64, 80);
			this.Password.Name = "Password";
			this.Password.PasswordChar = '*';
			this.Password.Size = new System.Drawing.Size(156, 20);
			this.Password.TabIndex = 13;
			this.Password.Text = "";
			this.Password.TextChanged += new System.EventHandler(this.Password_TextChanged);
			// 
			// label3
			// 
			this.label3.ImeMode = System.Windows.Forms.ImeMode.NoControl;
			this.label3.Location = new System.Drawing.Point(7, 84);
			this.label3.Name = "label3";
			this.label3.Size = new System.Drawing.Size(57, 14);
			this.label3.TabIndex = 12;
			this.label3.Text = "Password:";
			// 
			// Algorithm
			// 
			this.Algorithm.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
			this.Algorithm.DropDownWidth = 121;
			this.Algorithm.ItemHeight = 13;
			this.Algorithm.Location = new System.Drawing.Point(64, 52);
			this.Algorithm.Name = "Algorithm";
			this.Algorithm.Size = new System.Drawing.Size(156, 21);
			this.Algorithm.TabIndex = 7;
			this.Algorithm.SelectedIndexChanged += new System.EventHandler(this.Algorithm_OnSelIndexChanged);
			// 
			// label6
			// 
			this.label6.ImeMode = System.Windows.Forms.ImeMode.NoControl;
			this.label6.Location = new System.Drawing.Point(7, 55);
			this.label6.Name = "label6";
			this.label6.Size = new System.Drawing.Size(57, 14);
			this.label6.TabIndex = 1;
			this.label6.Text = "Algorithm:";
			// 
			// MethodsDetails
			// 
			this.MethodsDetails.Controls.Add(this.Method);
			this.MethodsDetails.Controls.Add(this.label11);
			this.MethodsDetails.Controls.Add(this.label6);
			this.MethodsDetails.Controls.Add(this.label3);
			this.MethodsDetails.Controls.Add(this.Password);
			this.MethodsDetails.Controls.Add(this.Algorithm);
			this.MethodsDetails.Controls.Add(this.LogonUser);
			this.MethodsDetails.Controls.Add(this.chkLocalMachine);
			this.MethodsDetails.FlatStyle = System.Windows.Forms.FlatStyle.System;
			this.MethodsDetails.Location = new System.Drawing.Point(16, 8);
			this.MethodsDetails.Name = "MethodsDetails";
			this.MethodsDetails.Size = new System.Drawing.Size(231, 148);
			this.MethodsDetails.TabIndex = 9;
			this.MethodsDetails.TabStop = false;
			this.MethodsDetails.Text = "Options";
			// 
			// Method
			// 
			this.Method.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
			this.Method.DropDownWidth = 121;
			this.Method.ItemHeight = 13;
			this.Method.Items.AddRange(new object[] {
														"Encrypt (Symm)",
														"Decrypt (Symm)",
														"Encrypt (Asym)",
														"Decrypt (Asym)",
														"Hash",
														"KeyedHash",
														"RNG",
														"Sign",
														"VerifySign",
														"SaltedHash",
														"VerifySaltedHash",
														"ProtectMemory",
														"UnprotectMemory",
													    "SecureString"});
			this.Method.Location = new System.Drawing.Point(64, 24);
			this.Method.Name = "Method";
			this.Method.Size = new System.Drawing.Size(156, 21);
			this.Method.TabIndex = 27;
			this.Method.SelectedIndexChanged += new System.EventHandler(this.Method_OnSelIndexChanged);
			// 
			// label11
			// 
			this.label11.ImeMode = System.Windows.Forms.ImeMode.NoControl;
			this.label11.Location = new System.Drawing.Point(8, 28);
			this.label11.Name = "label11";
			this.label11.Size = new System.Drawing.Size(48, 16);
			this.label11.TabIndex = 0;
			this.label11.Text = "Method:";
			// 
			// LogonUser
			// 
			this.LogonUser.DialogResult = System.Windows.Forms.DialogResult.Cancel;
			this.LogonUser.FlatStyle = System.Windows.Forms.FlatStyle.System;
			this.LogonUser.ImeMode = System.Windows.Forms.ImeMode.NoControl;
			this.LogonUser.Location = new System.Drawing.Point(148, 112);
			this.LogonUser.Name = "LogonUser";
			this.LogonUser.Size = new System.Drawing.Size(72, 23);
			this.LogonUser.TabIndex = 17;
			this.LogonUser.Text = "LogonUser";
			this.LogonUser.Click += new System.EventHandler(this.LogonUser_Click);
			// 
			// chkLocalMachine
			// 
			this.chkLocalMachine.FlatStyle = System.Windows.Forms.FlatStyle.System;
			this.chkLocalMachine.Location = new System.Drawing.Point(9, 112);
			this.chkLocalMachine.Name = "chkLocalMachine";
			this.chkLocalMachine.TabIndex = 17;
			this.chkLocalMachine.Text = "LocalMachine";
			// 
			// CloseForm
			// 
			this.CloseForm.DialogResult = System.Windows.Forms.DialogResult.Cancel;
			this.CloseForm.FlatStyle = System.Windows.Forms.FlatStyle.System;
			this.CloseForm.ImeMode = System.Windows.Forms.ImeMode.NoControl;
			this.CloseForm.Location = new System.Drawing.Point(608, 328);
			this.CloseForm.Name = "CloseForm";
			this.CloseForm.Size = new System.Drawing.Size(72, 23);
			this.CloseForm.TabIndex = 14;
			this.CloseForm.Text = "&Close";
			this.CloseForm.Click += new System.EventHandler(this.CloseForm_Click);
			// 
			// Execute
			// 
			this.Execute.FlatStyle = System.Windows.Forms.FlatStyle.System;
			this.Execute.ImeMode = System.Windows.Forms.ImeMode.NoControl;
			this.Execute.Location = new System.Drawing.Point(528, 328);
			this.Execute.Name = "Execute";
			this.Execute.Size = new System.Drawing.Size(72, 23);
			this.Execute.TabIndex = 13;
			this.Execute.Text = "&Execute";
			this.Execute.Click += new System.EventHandler(this.Execute_Click);
			// 
			// button1
			// 
			this.button1.DialogResult = System.Windows.Forms.DialogResult.Cancel;
			this.button1.FlatStyle = System.Windows.Forms.FlatStyle.System;
			this.button1.ImeMode = System.Windows.Forms.ImeMode.NoControl;
			this.button1.Location = new System.Drawing.Point(376, 328);
			this.button1.Name = "button1";
			this.button1.Size = new System.Drawing.Size(72, 23);
			this.button1.TabIndex = 15;
			this.button1.Text = "C&lear";
			this.button1.Click += new System.EventHandler(this.button1_Click);
			// 
			// button2
			// 
			this.button2.DialogResult = System.Windows.Forms.DialogResult.Cancel;
			this.button2.FlatStyle = System.Windows.Forms.FlatStyle.System;
			this.button2.ImeMode = System.Windows.Forms.ImeMode.NoControl;
			this.button2.Location = new System.Drawing.Point(452, 328);
			this.button2.Name = "button2";
			this.button2.Size = new System.Drawing.Size(72, 23);
			this.button2.TabIndex = 16;
			this.button2.Text = "E&xchange";
			this.button2.Click += new System.EventHandler(this.button2_Click);
			// 
			// CryptoTestHarness
			// 
			this.AcceptButton = this.Execute;
			this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
			this.CancelButton = this.CloseForm;
			this.ClientSize = new System.Drawing.Size(696, 360);
			this.Controls.Add(this.button2);
			this.Controls.Add(this.button1);
			this.Controls.Add(this.CloseForm);
			this.Controls.Add(this.Execute);
			this.Controls.Add(this.groupBox1);
			this.Controls.Add(this.gbResult);
			this.Controls.Add(this.MethodsDetails);
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
			this.Name = "CryptoTestHarness";
			this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
			this.Text = "Crypto Classes Test Harness";
			this.Load += new System.EventHandler(this.Form1_Load);
			this.groupBox1.ResumeLayout(false);
			this.gbResult.ResumeLayout(false);
			this.MethodsDetails.ResumeLayout(false);
			this.ResumeLayout(false);

		}
		#endregion

		/// <summary>
		/// The main entry point for the application.
		/// </summary>
		[STAThread]
		static void Main() 
		{
			Application.EnableVisualStyles();
			Application.Run(new CryptoTestHarness());
		}

		private void Execute_Click(object sender, System.EventArgs e)
		{
			try
			{
				switch( Method.SelectedItem.ToString() )
				{
					case "Encrypt (Symm)":
						DoEncryption();
						break;
					case "Decrypt (Symm)":
						DoDecryption();
						break;
					case "Encrypt (Asym)":
						DoEncryptionAsm();
						break;
					case "Decrypt (Asym)":
						DoDecryptionAsm();
						break;
					case "Hash":
						DoHash();
						break;
					case "KeyedHash":
						DoKeyedHash();
						break;
					case "RNG":
						DoRng();
						break;
					case "Sign":
						DoSign();
						break;
					case "VerifySign":
						DoVerifySign();
						break;
					case "SaltedHash":
						DoSaltedHash();
						break;
					case "VerifySaltedHash":
						DoVerifySaltedHash();
						break;
					case "ProtectMemory":
						DoProtectMemory();
						break;
					case "UnprotectMemory":
						DoUnprotectMemory();
						break;
					case "SecureString":
						DoSecureString();
						break;
				}
			}
			catch( Exception ex )
			{
				MessageBox.Show( this, ex.Message, "Exception", MessageBoxButtons.OK, MessageBoxIcon.Error );
			}
		}

		private void CloseForm_Click(object sender, System.EventArgs e)
		{
			this.Close(); //Application.Exit();
		}

		private void Form1_Load(object sender, System.EventArgs e)
		{			
			Method.SelectedIndex = 0;
			_bufferedInputData = InputData.Text;
		} private string _bufferedInputData; //Store the original InputData text.

		private void button1_Click(object sender, System.EventArgs e)
		{
			InputData.Text = _bufferedInputData;
			OutputData.Clear();
		}

		private void Method_OnSelIndexChanged(object sender, System.EventArgs e)
		{
			ArrayList symmAlgs = ArrayList.Adapter( Enum.GetNames( typeof(SymmetricAlgorithms) ) );
			ArrayList hashAlgs = ArrayList.Adapter( Enum.GetNames( typeof(HashAlgorithms) ) );
			ArrayList asymAlgs = ArrayList.Adapter( Enum.GetNames( typeof(AsymmetricAlgorithms) ) );

			switch( Method.SelectedItem.ToString() )
			{
				case "Encrypt (Symm)":
					Algorithm.DataSource = symmAlgs;
					Password.Enabled = true;
					break;
				case "Decrypt (Symm)":
					if( Algorithm.SelectedIndex > 0 && !symmAlgs.Contains( Algorithm.SelectedItem ) )
					{
						Algorithm.DataSource = symmAlgs;
					}
					if( OutputData.Text.Length > 0 )
					{
						InputData.Text = OutputData.Text;
					}
					Password.Enabled = true;
					break;
				case "Encrypt (Asym)":
					Algorithm.DataSource = new string[]{"RSA"};
					Password.Enabled = false;
					break;
				case "Decrypt (Asym)":
					Algorithm.DataSource = new string[]{"RSA"};
					if( OutputData.Text.Length > 0 )
					{
						InputData.Text = OutputData.Text;
					}
					Password.Enabled = false;
					break;
				case "Hash":
					Algorithm.DataSource = hashAlgs;
					Password.Enabled = false;
					break;
				case "KeyedHash":
					Algorithm.DataSource = Enum.GetNames( typeof(KeyedHashAlgorithms) );
					Password.Enabled = true;
					break;
				case "RNG":
					Algorithm.DataSource = null;
					Password.Enabled = false;
					break;
				case "Sign":
					Algorithm.DataSource = asymAlgs;
					Password.Enabled = false;
					break;
				case "Verify":
					if( Algorithm.SelectedIndex > 0 && !asymAlgs.Contains( Algorithm.SelectedItem ) )
					{
						Algorithm.DataSource = asymAlgs;
					}
					Password.Enabled = false;
					if( OutputData.Text.Length > 0 )
					{
						InputData.Text = OutputData.Text;
					}
					break;
				case "SaltedHash":
					Algorithm.DataSource = hashAlgs;
					Password.Enabled = false;
					break;
				case "VerifySaltedHash":
					if( Algorithm.SelectedIndex > 0 && !hashAlgs.Contains( Algorithm.SelectedItem ) )
					{
						Algorithm.DataSource = hashAlgs;
					}
					Password.Enabled = false;
					break;
				case "ProtectMemory":
					Algorithm.DataSource = null;
					Password.Enabled = false;
					break;
				case "UnprotectMemory":
					Algorithm.DataSource = null;
					Password.Enabled = false;
					break;
				case "SecureString":
					Algorithm.DataSource = null;
					Password.Enabled = false;
					break;
			}

			chkLocalMachine.Enabled = ( Password.Enabled && Password.Text.Length == 0 && Algorithm.SelectedIndex == 0 && Method.SelectedIndex < 2 );

		}

		#region "Methods Execution"

		private void DoEncryption()
		{
			if( Algorithm.SelectedIndex == 0 )
			{
				// Use default algorithm
				if( Password.Text.Length == 0 )
				{
					// Use ProtectedData.Protect method (DPAPI)
					if( !chkLocalMachine.Checked )
					{
						OutputData.Text = CryptoHelper.Encrypt( InputData.Text );
					}
					else
					{
						OutputData.Text = ProtectedData.Protect( InputData.Text, DataProtectionScope.LocalMachine );
					}
				}
				else
				{
					OutputData.Text = CryptoHelper.Encrypt( InputData.Text, Password.Text );
				}
			}
			else
			{
				OutputData.Text = CryptoHelper.Encrypt( InputData.Text, Password.Text, (SymmetricAlgorithm)CryptoConfig.CreateFromName( Algorithm.SelectedItem.ToString() ) );
			}
		}

		private void DoEncryptionAsm()
		{
			OutputData.Text = CryptoHelper.Encrypt( InputData.Text, CryptoHelper.RsaInstance.ExportParameters(false) );
		}

		private void DoDecryptionAsm()
		{
			OutputData.Text = CryptoHelper.Decrypt( InputData.Text, CryptoHelper.RsaInstance.ExportParameters(true) );
		}

		private void DoDecryption()
		{
			if( Algorithm.SelectedIndex == 0 )
			{
				// Use default algorithm
				if( Password.Text.Length == 0 )
				{
					// Use ProtectedData.Protect method (DPAPI)
					if( !chkLocalMachine.Checked )
					{
						OutputData.Text = CryptoHelper.Decrypt( InputData.Text );
					}
					else
					{
						OutputData.Text = ProtectedData.Unprotect( InputData.Text, DataProtectionScope.LocalMachine );
					}
				}
				else
				{
					OutputData.Text = CryptoHelper.Decrypt( InputData.Text, Password.Text );
				}
			}
			else
			{
				OutputData.Text = CryptoHelper.Decrypt( InputData.Text, Password.Text, (SymmetricAlgorithm)CryptoConfig.CreateFromName( Algorithm.SelectedItem.ToString() ) );
			}
		}

		private void DoHash()
		{
			if( Algorithm.SelectedIndex == 0 )
			{
				// Use default algorithm
				OutputData.Text = CryptoHelper.ComputeHash( InputData.Text );
			}
			else
			{
				OutputData.Text = CryptoHelper.ComputeHash( InputData.Text, (HashAlgorithm)CryptoConfig.CreateFromName( Algorithm.SelectedItem.ToString() ) );
			}
		}

		private void DoKeyedHash()
		{
			if( Algorithm.SelectedIndex == 0 )
			{
				OutputData.Text = CryptoHelper.ComputeKeyedHash( InputData.Text, Utility.DefaultEncoding.GetBytes( Password.Text ) );
			}
			else
			{
				OutputData.Text = CryptoHelper.ComputeKeyedHash( InputData.Text, (KeyedHashAlgorithm)CryptoConfig.CreateFromName( Algorithm.SelectedItem.ToString() ), Utility.DefaultEncoding.GetBytes( Password.Text ) );
			}
		}

		private void DoRng()
		{
			OutputData.Text = Utility.ToHexString( CryptoHelper.ComputeRandomBytes( 32 ) );
		}

		private void DoSign()
		{
			if( Algorithm.SelectedIndex == 0 )
			{
				// Use default algorithm
				OutputData.Text = CryptoHelper.Sign( InputData.Text );
			}
			else
			{
				_asymmAlg = (AsymmetricAlgorithm)CryptoConfig.CreateFromName( Algorithm.SelectedItem.ToString() );
				OutputData.Text = CryptoHelper.Sign( InputData.Text, _asymmAlg );
			}
		} private AsymmetricAlgorithm _asymmAlg = null; // Store the instance of the Asymm Alg to use when verifying the signature.

		private void DoVerifySign()
		{
			if( Algorithm.SelectedIndex == 0 )
			{
				// Use default algorithm
				OutputData.Text = CryptoHelper.VerifySignature( InputData.Text, OutputData.Text ).ToString();
			}
			else
			{
				OutputData.Text = CryptoHelper.VerifySignature( InputData.Text, OutputData.Text, _asymmAlg ).ToString();
			}
		}

		private void DoSaltedHash()
		{
			if( Algorithm.SelectedIndex == 0 )
			{
				// Use default algorithm
				OutputData.Text = CryptoHelper.ComputeSaltedHash( InputData.Text );
			}
			else
			{
				OutputData.Text = CryptoHelper.ComputeSaltedHash( InputData.Text, (HashAlgorithm)CryptoConfig.CreateFromName( Algorithm.SelectedItem.ToString() ) );
			}
		}

		private void DoVerifySaltedHash()
		{
			if( Algorithm.SelectedIndex == 0 )
			{
				// Use default algorithm
				OutputData.Text = CryptoHelper.VerifySaltedHash( InputData.Text, OutputData.Text ).ToString();
			}
			else
			{
				OutputData.Text = CryptoHelper.VerifySaltedHash( InputData.Text, OutputData.Text, (HashAlgorithm)CryptoConfig.CreateFromName( Algorithm.SelectedItem.ToString() ) ).ToString();
			}
		}

		private void DoProtectMemory()
		{
			byte[] input = Utility.DefaultEncoding.GetBytes( "0123456789ABCDEF" );
			ProtectedMemory.Protect( input );
			OutputData.Text = Utility.ToHexString( input );
		}

		private void DoUnprotectMemory()
		{
			byte[] output = Utility.FromHexString( OutputData.Text );
			ProtectedMemory.Unprotect( output );
			OutputData.Text = Utility.DefaultEncoding.GetString( output );
		}

		// For more info check:
		// http://blogs.msdn.com/shawnfa/archive/2004/05/27/143254.aspx
		// http://blogs.msdn.com/shawnfa/archive/2004/06/02/146915.aspx

		private void DoSecureString()
		{
			// char array build
			char[] chrs = InputData.Text.ToCharArray();
		
			// Single appends
			using( SecureString sec = new SecureString() )
			{
				for( int index = 0; index < chrs.Length; index++ )
				{
					sec.AppendChar( chrs[ index ] );
				}
				sec.MakeReadOnly();

				//sec.InsertAt( 1, 'A' );
				//sec.SetAt( 2, 'B' );
				//sec.RemoveAt( 1 );

				IntPtr p = SecureString.SecureStringToGlobalAllocUni( sec );
				try
				{
					// Unsecure managed string
					OutputData.Text = Marshal.PtrToStringUni( p );					
				}
				finally
				{
					SecureString.ZeroFreeGlobalAllocUni( p );
				}
			}
		}

		#endregion

		private void button2_Click(object sender, System.EventArgs e)
		{
			string buffer = OutputData.Text;
			OutputData.Text = InputData.Text;
			InputData.Text = buffer;
		}

		private void LogonUser_Click(object sender, System.EventArgs e)
		{
			try
			{
				System.Net.NetworkCredential credentials = UICredentialsHelper.PromptForCredentials( "Credentials", "Gimme your secret", this.Handle );
			
				if( credentials != null )
				{
					WindowsIdentity identity = WinAccessHelper.LogonUser( credentials );
					OutputData.Text = "Logged on account: " + identity.Name + Environment.NewLine + "Roles: " + String.Join( Environment.NewLine, WinAccessHelper.Roles( identity ) ) ;
				}
			}
			catch( Exception ex )
			{
				MessageBox.Show( this, ex.Message, "Exception", MessageBoxButtons.OK, MessageBoxIcon.Error );
			}
		}

		private void Password_TextChanged(object sender, System.EventArgs e)
		{
			chkLocalMachine.Enabled = (Password.Text.Length == 0);
		}

		private void Algorithm_OnSelIndexChanged(object sender, System.EventArgs e)
		{
			chkLocalMachine.Enabled = ( Password.Enabled && Password.Text.Length == 0 && Algorithm.SelectedIndex == 0 && Method.SelectedIndex < 2 );
		}
	}
}
