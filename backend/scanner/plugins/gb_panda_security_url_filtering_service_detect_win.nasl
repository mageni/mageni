###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panda_security_url_filtering_service_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Panda Security URL Filtering Service Version Detection (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809036");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-12-14 19:02:08 +0530 (Wed, 14 Dec 2016)");
  script_name("Panda Security URL Filtering Service Version Detection (Windows)");
  script_tag(name:"summary", value:"Detects the installed version of
  Panda Security URL Filtering Service.

  The script logs in via smb, searches for executable of
  Panda Security URL Filtering 'Panda_URL_Filteringb.exe' and gets the file
  version.");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Panda Software") &&
   !registry_key_exists(key:"SOFTWARE\panda_url_filtering") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Panda Software") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\panda_url_filtering"))
{
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Panda Security URL Filtering";
}

## Currently 64 bit app is not available for download
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Panda Security URL Filtering";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

pandaurlPath = registry_get_sz(item:"InstallLocation", key:key);
if(!pandaurlPath){
  exit(0);
}

pandaurlVer = fetch_file_version(sysPath:pandaurlPath,
                                  file_name: "\Panda_URL_Filteringb.exe");
if(pandaurlVer)
{
  set_kb_item(name:"PandaSecurity/URL/Filtering/Win/Ver", value:pandaurlVer);

  cpe = build_cpe(value:pandaurlVer, exp:"^([0-9.]+)", base:"cpe:/a:pandasecurity:panda_security_url_filtering:");
  if(isnull(cpe))
    cpe = "cpe:/a:pandasecurity:panda_security_url_filtering";

  register_product(cpe:cpe, location:pandaurlPath);
  log_message(data: build_detection_report(app:"Panda Security URL Filtering",
                                           version:pandaurlVer,
                                           install:pandaurlPath,
                                           cpe:cpe,
                                           concluded:pandaurlVer));
}

