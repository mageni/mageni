##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_bridge_cc_detect.nasl 10917 2018-08-10 16:48:12Z cfischer $
#
# Adobe Bridge CC Version Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.806870");
  script_version("$Revision: 10917 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 18:48:12 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-02-15 13:37:52 +0530 (Mon, 15 Feb 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Bridge CC Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe bridge cc on Windows.

  The script logs in via smb, searches for adobe in the registry, gets the
  Adobe bridge cc installation path from registry and fetches version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Adobe")){
  exit(0);
}

appkey = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\bridge.exe";
if(!registry_key_exists(key:appkey))
{
  appkey = "SOFTWARE\Wow6432Node\Windows\CurrentVersion\App Paths\bridge.exe";
  if(!registry_key_exists(key:appkey)){
    exit(0);
  }
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## 64bit and 32bit applications both installs in Wow6432Node
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

appPath = registry_get_sz(key:appkey, item:"Path");
if(appPath)
{
  brdVer = fetch_file_version(sysPath:appPath, file_name:"bridge.exe");
  if(!brdVer){
    exit(0);
  }
}

if(!isnull(brdVer))
{
  set_kb_item(name:"Adobe/Bridge/Ver", value:brdVer);

  cpe = build_cpe(value:brdVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:bridge_cc:");
  if(isnull(cpe)){
    cpe = "cpe:/a:adobe:bridge_cc";
  }

  if("x64" >< os_arch && "64 Bit" >< appPath)
  {
    set_kb_item(name:"Adobe/Bridge64/Ver", value:brdVer);

    cpe = build_cpe(value:brdVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:bridge_cc:x64:");
    if(isnull(cpe)){
      cpe = "cpe:/a:adobe:bridge_cc:x64";
    }
  }
  register_product(cpe:cpe, location:appPath);
  log_message(data: build_detection_report(app: "Adobe Bridge CC",
                                           version: brdVer,
                                           install: appPath,
                                           cpe: cpe,
                                           concluded: brdVer));
}
