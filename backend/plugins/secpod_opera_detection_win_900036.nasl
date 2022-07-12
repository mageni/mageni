###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_detection_win_900036.nasl 10902 2018-08-10 14:20:55Z cfischer $
#
# Opera Version Detection for Windows
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900036");
  script_version("$Revision: 10902 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:20:55 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Opera Version Detection for Windows");

  script_tag(name:"summary", value:"Detects the installed version of Opera on Windows.

  The script logs in via smb, searches for Opera in the registry and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

operaflag = TRUE; # nb: keep this as it is used later...

function OperaSet(operaVersion, operaName, operaPath){

  # Used in gb_opera_detect_portable_win.nasl to avoid doubled detections.
  # We're also stripping a possible ending backslash away as the portable NVT is getting
  # the file path without the ending backslash from WMI.
  tmp_location = tolower(operaPath);
  tmp_location = ereg_replace(pattern:"\\$", string:tmp_location, replace:'');
  set_kb_item(name:"Opera/Win/InstallLocations", value:tmp_location);
  # This is a special case as the opera.exe is placed within a version-based subdir
  set_kb_item(name:"Opera/Win/InstallLocations", value:tmp_location + "\" + operaVersion);

  set_kb_item(name:"Opera/Build/Win/Ver", value:operaVersion);
  ver = eregmatch(pattern:"^([0-9]+\.[0-9]+)", string:operaVersion);
  if(!isnull(ver[1])){

    set_kb_item(name:"Opera/Win/Version", value:ver[1]);

    cpe = build_cpe(value:ver[1], exp:"^([0-9.]+)", base:"cpe:/a:opera:opera_browser:");
    if(isnull(cpe))
      cpe = "cpe:/a:opera:opera_browser";

    register_product(cpe:cpe, location:operaPath);
    log_message(data:build_detection_report(app:operaName,
                                            version:ver[1],
                                            install:operaPath,
                                            cpe:cpe,
                                            concluded:operaVersion));
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_root = "SOFTWARE\";
}else if("x64" >< os_arch){
  key_root = "SOFTWARE\Wow6432Node\";
}

key = key_root + "Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key)){

  operaName = registry_get_sz(key:key + item, item:"DisplayName");
  if(operaName =~ "^Opera "){

    operaPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(operaPath){

      operaVer = fetch_file_version(sysPath:operaPath, file_name:"opera.exe");

      if(operaVer){
        OperaSet(operaVersion:operaVer, operaName:operaName, operaPath:operaPath);
        operaflag = FALSE;
      }else{
        operaVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        if(operaVer){
          OperaSet(operaVersion:operaVer, operaName:operaName, operaPath:operaPath);
          operaflag = FALSE;
        }
      }
    }else{

      operaPath = registry_get_sz(key:key_root + "Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
      if(operaPath){

        operaPath = operaPath + "\Opera" ;
        operaVer = fetch_file_version(sysPath:operaPath, file_name:"opera.exe");

        if(operaVer){
          OperaSet(operaVersion:operaVer, operaName:operaName, operaPath:operaPath);
          operaflag = FALSE;
        }
      }
    }
  }
}

if(operaflag){
  operaPath = registry_get_sz(key:key_root + "Netscape\Netscape Navigator\5.0, Opera\Main", item:"Install Directory");
  if(operaPath){
    operaPath += "\Opera";
    operaVer = fetch_file_version(sysPath:operaPath, file_name:"opera.exe");
    if(operaVer){
      OperaSet(operaVersion:operaVer, operaName:"Opera", operaPath:operaPath);
    }
  }
}
