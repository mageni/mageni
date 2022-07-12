###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_core_ftp_le_client_detect.nasl 10899 2018-08-10 13:49:35Z cfischer $
#
# Core FTP LE Client Version Detection (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810304");
  script_version("$Revision: 10899 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:49:35 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-12-08 11:49:16 +0530 (Thu, 08 Dec 2016)");
  script_name("Core FTP LE Client Version Detection (Windows)");
  script_tag(name:"summary", value:"Detects the installed version of
  Core FTP LE Client.

  The script logs in via smb, searches for 'Core FTP LE' in the
  registry, gets version and installation path information from the registry.");

  script_tag(name:"qod_type", value:"registry");

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

## Key based on architecture
if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  ftpName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Core FTP LE" >< ftpName)
  {
    ftpPath = registry_get_sz(key:key + item, item:"UninstallString");
    if(ftpPath)
    {
      ftpPath = ftpPath - "uninstall.exe";
      ftpPath = ereg_replace(pattern:'"', replace:"", string:ftpPath);

      ##coreftp.exe --> CoreFTP Client, coresrvr.exe --> CoreFTP server
      ftpVer = fetch_file_version(sysPath:ftpPath, file_name:"coreftp.exe");
    }
    else
    {
      ftpPath = "Couldn find the install location";
    }

    if(ftpVer)
    {
      set_kb_item(name:"Core/FTP/Client/Win/Ver", value:ftpVer);

      cpe = build_cpe(value:ftpVer, exp:"^([0-9.]+)", base:"cpe:/a:coreftp:core_ftp:");
      if(isnull(cpe))
        cpe = "cpe:/a:coreftp:core_ftp";

      register_product(cpe:cpe, location:ftpPath);

      log_message(data: build_detection_report(app: "Core FTP LE",
                                               version: ftpVer,
                                               install: ftpPath,
                                               cpe: cpe,
                                               concluded: ftpVer));
    }
  }
}
