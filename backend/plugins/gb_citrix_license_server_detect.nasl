###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_license_server_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Citrix License Server Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-05-28
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801853");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Citrix License Server Version Detection");


  script_tag(name:"summary", value:"This script finds the installed Citrix License Server version and saves the
version in KB.

The script logs in via smb, searches for Citrix in the registry and gets the
version from 'Version' string from the registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Citrix\LicenseServer\Install");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Wow6432Node\Citrix\LicenseServer\Install");
}

if(isnull(key_list)){
    exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Citrix\LicenseServer"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Citrix\LicenseServer"))
  {
    exit(0);
  }
}

foreach key (key_list)
{
  ciVer = registry_get_sz(key:key, item:"Version");

  if(ciVer)
  {
    ciPath = registry_get_sz(key:key, item:"LS_Install_Dir");
    if(!ciPath){
      ciPath = "Couldn find the install location from registry";
    }

    set_kb_item(name:"Citrix/License/Server/Ver", value:ciVer);

    cpe = build_cpe(value:ciVer, exp:"^([0-9.]+)", base:"cpe:/a:citrix:licensing_administration_console:");
    if(isnull(cpe))
      cpe = "cpe:/a:citrix:licensing_administration_console";

    register_product(cpe:cpe, location:ciPath);
    log_message(data: build_detection_report(app: "Citrix License Server",
                                                 version:ciVer,
                                                 install: ciPath ,
                                                 cpe:cpe,
                                                 concluded:ciVer));
  }
}
