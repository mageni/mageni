###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_old_adobe_reader_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Adobe Reader Old Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804623");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-06-04 14:46:32 +0530 (Wed, 04 Jun 2014)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Reader Old Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Adobe Reader (less or equal to version 6.0)
on Windows.

The script logs in via smb, searches for Adobe Reader in the registry,
gets the path of '.exe' from registry and fetches version from executable.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\AcroRd32.exe");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\AcroRd32.exe");
}

if(isnull(key_list)){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Adobe")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Adobe")){
    exit(0);
  }
}

foreach key (key_list)
{
  readPath = registry_get_sz(key:key, item:"Path");

  readPath = split(readPath, sep:";",keep:FALSE);
  readPath = readPath[0];

  if(readPath)
  {
    readVer = fetch_file_version(sysPath:readPath, file_name: "AcroRd32.exe");
    readVer = eregmatch(pattern:"(^[0-6]\.[0-9]+\.[0-9]+)", string: readVer);
    if(readVer[0])
    {
      set_kb_item(name:"Adobe/Reader-Old/Ver", value:readVer[0]);

      cpe = build_cpe(value:readVer[0], exp:"^([0-9.]+)", base:"cpe:/a:adobe:acrobat_reader:");
      if(isnull(cpe))
        cpe = "cpe:/a:adobe:acrobat_reader";

      register_product(cpe:cpe, location:readPath);

      log_message(data: build_detection_report(app:"Adobe Reader",
                                               version:readVer[0],
                                               install:readPath,
                                               cpe:cpe,
                                               concluded:readVer[0]));
    }
  }
}
