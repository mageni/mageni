###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_norton_utilities_detect_win.nasl 12203 2018-11-02 14:42:44Z bshakeel $
#
# Norton Utilities Version Detection (Windows)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.814302");
  script_version("$Revision: 12203 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-02 15:42:44 +0100 (Fri, 02 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-02 16:36:51 +0530 (Fri, 02 Nov 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Norton Utilities Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Norton
  Utilities on Windows. The script logs in via smb, searches for 'Norton Utilities'
  and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Norton Utilities" >< appName)
  {
    norPath = registry_get_sz(key:key + item, item:"InstallLocation");
    norVer = fetch_file_version(sysPath:norPath, file_name:"nu.exe");
    if(!norVer){
      norVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    }
    if(!norPath){
      norPath = "Could not find the install location from registry";
    }

    if(norVer)
    {
      set_kb_item(name:"Norton/Utilities/Win/Ver", value:norVer);
      cpe = build_cpe(value:norVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:norton_utilities:");
      if(isnull(cpe))
        cpe = "cpe:/a:symantec:norton_utilities:";

      register_product(cpe: cpe, location: norPath);
      log_message(data: build_detection_report(app: "Norton Utilities",
                                               version: norVer,
                                               install: norPath,
                                               cpe: cpe,
                                               concluded: norVer));
    }
  }
}
