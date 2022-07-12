##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_java_dir_server_detect_win.nasl 12974 2019-01-08 13:06:45Z cfischer $
#
# Sun Java Directory Server Version Detection (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated to Detect 6 Series Versions
#  - By Sharath S <sharaths@secpod.com> On 2009-12-31 #6445
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-09-02
# Updated to support 32 and 64 bit.
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900492");
  script_version("$Revision: 12974 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 14:06:45 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Sun Java Directory Server Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of Sun Java Directory Server.

  This script detects the version of Directory Server and sets the reuslt in KB.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\";
}else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\";
}

key1 = key + "Sun Microsystems\DirectoryServer\";
key2 = key + "Microsoft\Windows\CurrentVersion\Uninstall\Directory Server\";

if(registry_key_exists(key:key1)){

  foreach item (registry_enum_keys(key:key1)){

    ver = eregmatch(pattern:"([0-9]\.[0-9.]+)", string:item);
    if(!isnull(ver[1])){
      set_kb_item(name:"Sun/JavaDirServer/Win/Ver", value:ver[1]);
      path = "Not able to find the install Location";
      register_and_report_cpe( app:"Sun Java Directory Server", ver:ver[1], concluded:ver[1], base:"cpe:/a:sun:java_system_directory_server:", expr:"^([0-9.]+)", insloc:path );
    }
  }
}else if(registry_key_exists(key:key2)){

  appregCheck = registry_get_sz(key:key2, item:"DisplayName");
  if("Directory Server" >< appregCheck){

    infPath = registry_get_sz(key:key2, item:"UninstallString");
    infPath = ereg_replace(pattern:'"', string:infPath, replace:"");
    infFile = infPath - "uninstall_dirserver.exe" + "setup\slapd\slapd.inf";
    infContent = smb_read_file(fullpath:infFile, offset:0, count:256);
    if("Directory Server" >< infContent){

      appVer = eregmatch(pattern:"System Directory Server ([0-9]\.[0-9.]+)", string:infContent);

      if(!isnull(appVer[1])){
        set_kb_item(name:"Sun/JavaDirServer/Win/Ver", value:appVer[1]);
        register_and_report_cpe( app:appregCheck, ver:appVer[1], concluded:appVer[1], base:"cpe:/a:sun:java_system_directory_server:", expr:"^([0-9.]+)", insloc:infPath );
      }
    }
  }
}

exit(0);