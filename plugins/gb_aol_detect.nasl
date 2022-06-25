###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aol_detect.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# America Online (AOL) Version Detection (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-05-20
# Updated according to CR57 and to support 32 and 64 bit.
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
  script_oid("1.3.6.1.4.1.25623.1.0.801025");
  script_version("$Revision: 10915 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("America Online (AOL) Version Detection (Windows)");


  script_tag(name:"summary", value:"Detects the installed version of America Online (AOL) on Windows.

The script logs in via smb, searches for America Online in the registry
and gets the install location and extract version from the file.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

key = "SOFTWARE\America Online\AOL";
if(!registry_key_exists(key:key))
{
  key = "SOFTWARE\Wow6432Node\America Online\AOL";
  if(!registry_key_exists(key:key)){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\America Online\AOL\";
}

## Presently America Online (AOL) 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\America Online\AOL\";
}

appPath = registry_get_sz(key:key + "CurrentVersion", item:"AppPath");

if(appPath != NULL)
{
  version = fetch_file_version(sysPath: appPath, file_name: "aol.exe");

  if(version != NULL)
  {
    set_kb_item(name:"AOL/Ver", value:version);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:aol:internet_software:");
    if(isnull(cpe))
      cpe = "cpe:/a:aol:internet_software";

    register_product(cpe:cpe, location:appPath);

    log_message(data: build_detection_report(app: "America Online (AOL)",
                                             version: version,
                                             install: appPath,
                                             cpe: cpe,
                                             concluded: version));
  }
}
