###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_expression_web_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Microsoft Expression Web Detection
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-06-24
# Updated plugin completely according to CR57 and to support 32 and 64 bit
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802885");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-07-11 18:35:57 +0530 (Wed, 11 Jul 2012)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Expression Web Detection");


  script_tag(name:"summary", value:"Detects the installed version of Microsoft Expression Web.

The script logs in via smb, searches for Microsoft Expression Web and
in the registry and gets the version from 'Version' string in registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently Adobe RoboHelp 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ewName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Microsoft Expression Web" >< ewName)
  {
    ewVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(ewVer)
    {
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insPath){
        insPath = "Could not find the install location from registry";
      }

      set_kb_item(name:"MS/Expression-Web/Ver", value:ewVer);

      cpe = build_cpe(value:ewVer, exp:"^([0-9.]+[a-z0-9]*)", base:"cpe:/a:microsoft:expression_web:");
      if(!cpe){
        cpe = "cpe:/a:microsoft:expression_web";
      }

      register_product(cpe:cpe, location:insPath);

      log_message(data: build_detection_report(app:"Microsoft Expression Web",
                                              version:ewVer, install:insPath, cpe:cpe,
                                              concluded: ewVer));
    }
  }
}
