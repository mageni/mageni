###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibackup_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# iBackup Version Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805201");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-12-01 12:55:19 +0530 (Mon, 01 Dec 2014)");
  script_tag(name:"qod_type", value:"registry");
  script_name("iBackup Version Detection (Windows)");

  script_tag(name:"summary", value:"This script detects the installed
  version of iBackup on Windows and sets the result in KB.

  The script logs in via smb, searches for iBackup in the registry
  and gets the version from file.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently 64bit application is not available
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if("IBackup" >< appName)
  {
    insloc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(insloc)
    {
      ibackupVer = fetch_file_version(sysPath:insloc, file_name:"ib_win.exe");
      if(ibackupVer)
      {
        set_kb_item(name:"iBackup/Win/Ver", value:ibackupVer);

        cpe = build_cpe(value:ibackupVer, exp:"^([0-9.]+)", base:"cpe:/a:pro_softnet_corporation:ibackup:");
        if(isnull(cpe))
          cpe = "cpe:/a:pro_softnet_corporation:ibackup";

        register_product(cpe:cpe, location:insloc);

        log_message(data: build_detection_report(app: "IBackup",
                                                 version: ibackupVer,
                                                 install: insloc,
                                                 cpe: cpe,
                                                 concluded: ibackupVer));
      }
    }
  }
}
