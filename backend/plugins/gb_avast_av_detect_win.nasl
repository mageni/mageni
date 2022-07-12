###############################################################################
# OpenVAS Vulnerability Test
#
# avast! AntiVirus Version Detection (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-06-24
# Updated plugin completely according to CR57 and to support 32 and 64 bit
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801110");
  script_version("2019-05-20T11:12:48+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("avast! AntiVirus Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of avast! AntiVirus on Windows.

The script logs in via smb, searches for avast and gets the
version from 'DisplayVersion' string in registry.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("version_func.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## 64bit and 32bit applications both installs in Wow6432Node
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach path (make_list("Avast", "Avast Antivirus", "avast!", "avast5"))
{
  avastName = registry_get_sz(key:key + path, item:"DisplayName");
  if("avast! (Free )?Antivirus" >< avastName || "Avast Free Antivirus" >< avastName)
  {
    avastVer = registry_get_sz(key:key + path, item:"DisplayVersion");
    avastPath = registry_get_sz(key:key + path, item:"DisplayIcon");
    avastPath = avastPath - "\AvastUI.exe";
    if(avastVer !~ "^([0-9]\.[0-9]+\.[0-9]+\.[0-9]+)" && avastPath){
      avastVer = fetch_file_version(sysPath:avastPath , file_name: "AvastUI.exe");
    }

    if(!isnull(avastVer))
    {
      set_kb_item(name:"Avast!/AV/Win/Ver", value:avastVer);

      cpe = build_cpe(value:avastVer, exp:"^([0-9.]+)", base:"cpe:/a:avast:avast_antivirus:");
      if(isnull(cpe)){
        cpe = "cpe:/a:avast:avast_antivirus";
      }

      if("x64" >< os_arch && "x86" >!< avastPath)
      {
        set_kb_item(name:"Avast!/AV64/Win/Ver", value:avastVer);

        cpe = build_cpe(value:avastVer, exp:"^([0-9.]+)", base:"cpe:/a:avast:avast_antivirus:x64:");
        if(isnull(cpe)){
          cpe = "cpe:/a:avast:avast_antivirus:x64";
        }
      }
      register_product(cpe:cpe, location:avastPath);

      log_message(data: build_detection_report(app: avastName,
                                               version: avastVer,
                                               install: avastPath,
                                               cpe: cpe,
                                               concluded: avastVer));
      exit(0);
    }
  }
}
