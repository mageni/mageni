###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# PHP Version Detection (Windows, local)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.902435");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_name("PHP Version Detection (Windows, local)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of PHP.

  The script logs in via smb, searches for PHP in the registry and gets the
  version from registry");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\PHP\";
if(!registry_key_exists(key:key))
{
  key = "SOFTWARE\Wow6432Node\PHP\";
  if(!registry_key_exists(key:key)){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

phpVer = registry_get_sz(key:key, item:"version");
phpPath = registry_get_sz(key:key, item:"InstallDir");
if(!phpPath){
  phpPath = "Could not find the install location from registry";
}
#nb: older versions
if(!phpVer)
{
  if(!registry_key_exists(key:key)){
    exit(0);
  }

  foreach item (registry_enum_keys(key:key))
  {
    phpName = registry_get_sz(key:key + item, item:"DisplayName");

    if("PHP" >< phpName){
      phpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    }
  }
}

if( phpVer != NULL ) {
  if( "RC" >< phpVer ) {
    version = eregmatch(string:phpVer, pattern:"([0-9.]+)(RC([0-9]+))?");
    version[2] = tolower(version[2]);
    ver = version[1] + version[2];
    phpVer = version[1] + "." + version[2];
  }

  set_kb_item( name:"PHP/Ver/win", value:phpVer );
  set_kb_item( name:"php/installed", value:TRUE );

  if( ver ) {
    cpe = build_cpe( value:ver, exp:"([0-9.]+)(RC([0-9]+))?", base:"cpe:/a:php:php:" );
  } else {
    cpe = build_cpe( value:phpVer, exp:"^([0-9.]+)", base:"cpe:/a:php:php:" );
  }

  if( isnull( cpe ) )
    cpe = "cpe:/a:php:php";

  register_product( cpe:cpe, location:phpPath, port:0 );

  log_message( data:build_detection_report( app:"PHP",
                                            version:phpVer,
                                            install:phpPath,
                                            cpe:cpe,
                                            concluded:version[0] ),
                                            port:0 );
}

exit( 0 );
