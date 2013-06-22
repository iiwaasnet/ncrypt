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
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Permissions;
using System.Runtime.InteropServices;

using NCrypto.Security.Cryptography;

// APTCA: Allows strong-named assemblies to be called by partially trusted code. 
// Without this declaration, only fully trusted callers are able to use such 
// assemblies.
// WARNING: The use of this attribute implies a futher check of all of public methods
// for security vulnerabilities with rigorous code review.
// Other alternatives for solving this problem are for example using the 
// application’s private assembly and just configure CAS policy to give more 
// rights to that assembly (based, for example, on assembly hash). 
// After that you can demand some specific permission before asserting 
// permission required to access protected resource or run operation that 
// requires high level of trust. And you don’t need dancing around APTCA/SN/GAC stuff. 

//[assembly: System.Security.AllowPartiallyTrustedCallers]

#region "Assembly General Information"

[assembly: AssemblyTitle("NCrypto.Security.Cryptography")]
[assembly: AssemblyDescription("Cryptography - Contains the helper classes that acts as managed cryptography API wrappers.")]

[assembly: ComVisible(false)]
[assembly: CLSCompliant(true)]

#if DEBUG		
[assembly: AssemblyConfiguration("Debug")]
#else
[assembly: AssemblyConfiguration("Release")]
#endif

#endregion

#region "Version Information"

[assembly: AssemblyVersion("1.2.0.0")]

#endregion


#region "Permissions Section"

// This is the minimal security permission 
// ControlPrincipal is required by Win32AccessHelper.LogonUser method.
//[assembly: SecurityPermission( SecurityAction.RequestMinimum, 
//							   Flags = SecurityPermissionFlag.Execution | 
//									   SecurityPermissionFlag.ControlPrincipal )]

//// This permission is for UICredentialsHelper class access.
//[assembly:UIPermission(SecurityAction.RequestMinimum,
//					   Window=UIPermissionWindow.SafeTopLevelWindows)]

// There will be a demmand for CryptographicPermission with different flags
// depending on the method called.

#endregion