###############################################################################
# OpenVAS Vulnerability Test
#
# SMB Windows Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103621");
  script_version("2019-05-15T09:55:33+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-15 09:55:33 +0000 (Wed, 15 May 2019)");
  script_tag(name:"creation_date", value:"2012-12-11 10:59:09 +0200 (Tue, 11 Dec 2012)");
  script_name("SMB Windows Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"Detection of installed Windows version");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");

SCRIPT_DESC = "SMB Windows Detection";
banner_type = "Registry access via SMB";

winVal = get_kb_item( "SMB/WindowsVersion" );
if( ! winVal ) exit( 0 );

winName = get_kb_item( "SMB/WindowsName" );
csdVer  = get_kb_item( "SMB/CSDVersion" );
arch    = get_kb_item( "SMB/Windows/Arch" );
build   = get_kb_item( "SMB/WindowsBuild" );

if( isnull( csdVer ) ) {
  csdVer = "";
} else {
  csdVer = eregmatch( pattern:"Service Pack [0-9]+", string:csdVer );
  if( ! isnull( csdVer[0] ) ) csdVer = csdVer[0];
}

function register_win_version( cpe_base, win_vers, servpack, os_name, os_edition, os_branch, is64bit ) {

  local_var cpe_base, win_vers, servpack, os_name, os_edition, os_branch, is64bit;
  local_var cpe;

  servpack = ereg_replace( string:servpack, pattern:"Service Pack ", replace:"sp", icase:TRUE );

  if( ! isnull( servpack ) && strlen( servpack ) > 0 ) {

    if( ! win_vers )
      win_vers = "-";

    cpe = cpe_base + ":" + win_vers + ":" + servpack;
    if( is64bit && os_edition )
      cpe += ":" + os_edition + "_x64";
    else if( is64bit )
      cpe += ":x64";

  } else if( ! isnull( win_vers ) && strlen( win_vers ) > 0 ) {
    cpe = cpe_base + ":" + win_vers;
    if( os_edition && os_branch ) {
      cpe += ":" + os_branch + ":" + os_edition;
      if( is64bit )
        cpe += "_x64";
    } else if( os_edition ) {
      cpe += ":-:" + os_edition;
      if( is64bit )
        cpe += "_x64";
    } else if( os_branch ) {
      cpe += ":" + os_branch;
      if( is64bit )
        cpe += ":x64";
    } else if( is64bit ) {
      cpe += ":-:x64";
    }
  } else {
    cpe = cpe_base;
    if( os_edition && os_branch ) {
      cpe += ":-:" + os_branch + ":" + os_edition;
      if( is64bit )
        cpe += "_x64";
    } else if( os_edition ) {
      cpe += ":-:-:" + os_edition;
      if( is64bit )
        cpe += "_x64";
    } else if( os_branch ) {
      cpe += ":-:" + os_branch;
      if( is64bit )
        cpe += ":x64";
    } else if( is64bit ) {
      cpe += ":-:-:x64";
    }
  }

  register_and_report_os( os:os_name, cpe:cpe, banner_type:banner_type, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 ); # We don't need to continue here after the first match
}

if( winVal == "4.0" ) {
  register_win_version( cpe_base:"cpe:/o:microsoft:windows_nt", win_vers:"4.0", servpack:csdVer, os_name:winName );
}

if( winVal == "5.0" && "Microsoft Windows 2000" >< winName ) {
  register_win_version( cpe_base:"cpe:/o:microsoft:windows_2000", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "5.1" && "Microsoft Windows XP" >< winName ) {
  register_win_version( cpe_base:"cpe:/o:microsoft:windows_xp", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "5.2" && "Microsoft Windows XP" >< winName && "x64" >< arch ) {
  register_win_version( cpe_base:"cpe:/o:microsoft:windows_xp", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
}

if( winVal == "5.2" && "Microsoft Windows Server 2003" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2003", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2003", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.0" && "Windows Vista" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_vista", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_vista", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.0" && "Windows Server (R) 2008" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2008", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2008", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.1" && "Windows 7" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_7", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_7", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.1" && "Windows Server 2008 R2" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2008", win_vers:"r2", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2008", win_vers:"r2", servpack:csdVer, os_name:winName );
}

if( winVal == "6.2" && "Windows Server 2012" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2012", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2012", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.2" && "Windows 8" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_8", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_8", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.3" && "Windows Server 2012 R2" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2012", win_vers:"r2", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2012", win_vers:"r2", servpack:csdVer, os_name:winName );
}

if( winVal == "6.3" && "Windows 8.1" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_8.1", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_8.1", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.3" && "Windows Embedded 8.1" >< winName ) {
  register_win_version( cpe_base:"cpe:/o:microsoft:windows_embedded_8.1", win_vers:"", servpack:csdVer, os_name:winName );
} else if( ( "Windows Embedded" >< winName ) ) {
  register_win_version( cpe_base:"cpe:/o:microsoft:windows_embedded", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.3" && "Windows 10" >< winName ) {

  vers = "";
  os_branch = "";
  os_edition = "";
  if( ver = get_version_from_build( string:build, win_name:"win10" ) )
    vers = ver;

  if( "LTSB" >< winName )
    os_branch = "ltsb";
  else if( "LTSC" >< winName )
    os_branch = "ltsc";
  else
    os_branch = "cb";

  if( "Enterprise" >< winName )
    os_edition = "enterprise";
  else if( "Education" >< winName )
    os_edition = "education";
  else if( "Home" >< winName )
    os_edition = "home";
  else if( "Pro" >< winName )
    os_edition = "pro";
  else
    os_edition += "unknown_edition";

  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_10", win_vers:vers, servpack:csdVer, os_name:winName, os_branch:os_branch, os_edition:os_edition, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_10", win_vers:vers, servpack:csdVer, os_name:winName, os_branch:os_branch, os_edition:os_edition );
}

if( winVal == "6.3" && "Windows Server 2016" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2016", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2016", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.3" && "Windows Server 2019" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2019", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2019", win_vers:"", servpack:csdVer, os_name:winName );
}

## Fallback if none of the above is matching, also report as "unknown" OS.
## Some embedded XP versions are only providing a winVal but not a winName. Avoid a unknown reporting for those and just register the OS
if( winVal && winName ) {
  register_unknown_os_banner( banner:"winVal = " + winVal + ", winName = " + winName + ", arch = " + arch, banner_type_name:banner_type, banner_type_short:"smb_win_banner" );
}

register_win_version( cpe_base:"cpe:/o:microsoft:windows", win_vers:"", servpack:csdVer, os_name:winName );

#nb: If updating / adding OS detection here please also update gb_windows_cpe_detect.nasl and smb_reg_service_pack.nasl

exit( 0 );
