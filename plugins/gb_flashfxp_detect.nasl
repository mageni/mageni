###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flashfxp_detect.nasl 10899 2018-08-10 13:49:35Z cfischer $
#
# FlashFXP Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802969");
  script_version("$Revision: 10899 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:49:35 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-09-26 12:00:40 +0530 (Wed, 26 Sep 2012)");
  script_tag(name:"qod_type", value:"registry");
  script_name("FlashFXP Version Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"summary", value:"Detects the installed version of FlashFXP.

The script logs in via smb, searches for FlashFXP in the registry and
gets the version from registry");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\FlashFXP")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");

  if("FlashFXP" >< name)
  {
    flashVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(flashVer)
    {
      flashPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!flashPath){
        flashPath = 'Could not find the install path from registry';
      }

      set_kb_item(name:"FlashFXP/Ver", value:flashVer);

      cpe = build_cpe(value:flashVer, exp:"^([0-9.]+)", base:"cpe:/a:flashfxp:flashfxp:");
      if(isnull(cpe))
        cpe = "cpe:/a:flashfxp:flashfxp";

      register_product(cpe:cpe, location:flashPath);

      log_message(data: build_detection_report(app:"FlashFXP",
                                               version:flashVer, install:flashPath,
                                               cpe:cpe, concluded: flashVer));

      exit(0);
    }
  }
}
