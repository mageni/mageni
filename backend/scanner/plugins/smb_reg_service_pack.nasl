###############################################################################
# OpenVAS Vulnerability Test
#
# SMB Registry : Windows Build Number and Service Pack Version
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2008 Renaud Deraison
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10401");
  script_version("2019-05-15T09:55:33+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-15 09:55:33 +0000 (Wed, 15 May 2019)");
  script_tag(name:"creation_date", value:"2008-08-27 12:14:14 +0200 (Wed, 27 Aug 2008)");
  script_name("SMB Registry : Windows Build Number and Service Pack Version");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_copyright("This script is Copyright (C) 2008 Renaud Deraison");
  # Don't add a dependency to os_detection.nasl. This will cause a dependency cycle.
  script_dependencies("smb_registry_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_access");

  script_xref(name:"URL", value:"https://www.mageni.net/docs");

  script_tag(name:"summary", value:"Detection of the installed Windows build number and
  Service Pack version.

  The script logs in via SMB, reads various registry keys to retrieve the
  Windows build number and Service Pack version.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");

SCRIPT_DESC = "SMB Registry : Windows Service Pack version";

access = get_kb_item( "SMB/registry_access");
if( ! access ) exit( 0 );

winVal = registry_get_sz( key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"CurrentVersion" );
if( winVal ) set_kb_item( name:"SMB/WindowsVersion", value:winVal );

winBuild = registry_get_sz( key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"CurrentBuild" );
if( winBuild ) set_kb_item( name:"SMB/WindowsBuild", value:winBuild );

winName = registry_get_sz( key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"ProductName" );

if( winName ) {
  set_kb_item( name:"SMB/WindowsName", value:winName );
  os_str = winName;
  if( winVal ) os_str += ' ' + winVal;
  replace_kb_item( name:"Host/OS/smb", value:os_str );
  replace_kb_item( name:"SMB/OS", value:os_str );
}

csdVer = registry_get_sz( key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"CSDVersion" );
if( ! csdVer ) csdVer = "NO_Service_Pack";

key = "SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
if( ! registry_key_exists( key:key ) ) {
  report  = "It was not possible to access the registry key 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'";
  report += " due to e.g. missing access permissions of the scanning user. Authenticated scans might be incomplete, ";
  report += "please check the references how to correctly configure the user account for Authenticated scans.";
  set_kb_item( name:"SMB/registry_access_missing_permissions/report", value:report );
  set_kb_item( name:"SMB/registry_access_missing_permissions", value:TRUE );
  log_message( port:0, data:report );
  exit( 0 );
}

arch = registry_get_sz( key:key, item:"PROCESSOR_ARCHITECTURE" );
if( "64" >< arch ) {
  set_kb_item( name:"SMB/Windows/Arch", value:"x64" );
} else if( "x86" >< arch ) {
  set_kb_item( name:"SMB/Windows/Arch", value:"x86" );
} else {
  # nb: Sometimes there seems to be not enough permissions for that registry key to gather the
  # processor architecture so have a fallback for this case.
  if( ! arch ) {
    set_kb_item( name:"SMB/Windows/Arch", value:"unknown/failed to read PROCESSOR_ARCHITECTURE from key " + key );
  } else {
    set_kb_item( name:"SMB/Windows/Arch", value:arch );
  }
}

if( csdVer && "NO_Service_Pack" >!< csdVer ) {

  set_kb_item( name:"SMB/CSDVersion", value:csdVer );
  csdVer = eregmatch( pattern:"Service Pack [0-9]+", string:csdVer );
  if( ! isnull( csdVer[0] ) ) csdVer = csdVer[0];

  if( winVal == "4.0" ) {
    set_kb_item( name:"SMB/WinNT4/ServicePack", value:csdVer );
  }

  if( winVal == "5.0" && "Microsoft Windows 2000" >< winName ) {
    set_kb_item( name:"SMB/Win2K/ServicePack", value:csdVer );
  }

  if( winVal == "5.1" && "Microsoft Windows XP" >< winName ) {
    set_kb_item( name:"SMB/WinXP/ServicePack", value:csdVer );
  }

  if( winVal == "5.2" && "Microsoft Windows Server 2003" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/Win2003/ServicePack", value:csdVer );
  }

  if( winVal == "5.2" && "Microsoft Windows Server 2003" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2003x64/ServicePack", value:csdVer );
  }

  if( winVal == "5.2" && "Microsoft Windows XP" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/WinXPx64/ServicePack", value:csdVer );
  }

  if( winVal == "6.0" && "Windows Vista" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/WinVista/ServicePack", value:csdVer );
  }

  if( winVal == "6.0" && "Windows Vista" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/WinVistax64/ServicePack", value:csdVer );
  }

  if( winVal == "6.0" && "Windows Server (R) 2008" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/Win2008/ServicePack", value:csdVer );
  }

  if( winVal == "6.0" && "Windows Server (R) 2008" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2008x64/ServicePack", value:csdVer );
  }

  if( winVal == "6.1" && "Windows 7" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/Win7/ServicePack", value:csdVer );
  }

  if( winVal == "6.1" && "Windows 7" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win7x64/ServicePack", value:csdVer );
  }

  if( winVal == "6.1" && "Windows Server 2008 R2" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2008R2/ServicePack", value:csdVer );
  }

  if( winVal == "6.2" && "Windows Server 2012" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2012/ServicePack", value:csdVer );
  }

  if( winVal == "6.2" && "Windows 8" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/Win8/ServicePack", value:csdVer );
  }

  if( winVal == "6.2" && "Windows 8" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win8x64/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows 8.1" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/Win8.1/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows 8.1" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win8.1x64/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows 10" >< winName && "x86" >< arch ) {
    set_kb_item( name:"SMB/Win10/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows 10" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win10x64/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows Server 2012 R2" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2012R2/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows Server 2016" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2016/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows Server 2019" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2019/ServicePack", value:csdVer );
  }

  if( winVal == "6.3" && "Windows Server 2022" >< winName && "64" >< arch ) {
    set_kb_item( name:"SMB/Win2022/ServicePack", value:csdVer );
  }

  #nb: If updating / adding an OS here also update gb_windows_cpe_detect.nasl and gb_smb_windows_detect.nasl
}

if( ! isnull( os_str ) && ! isnull( csdVer ) && "NO_Service_Pack" >!< csdVer ) {
  report = os_str + " is installed with " + csdVer;
  log_message( port:0, data:report );
}

# At least Windows 10 don't have any Services Packs but just build numbers
else if( ! isnull( os_str ) && "Windows 10" >< winName && winBuild ) {
  set_kb_item( name:"SMB/Windows/ServicePack", value:"0" );
  report = os_str + " is installed with build number " + winBuild;
  log_message( port:0, data:report );
}

else if( ! isnull( os_str ) && ! isnull( csdVer ) && "NO_Service_Pack" >< csdVer ) {
  SP = "0";
  set_kb_item( name:"SMB/Windows/ServicePack", value:SP );
  report = os_str + " is installed with Service Pack " + SP;
  log_message( port:0, data:report );
}

exit( 0 );