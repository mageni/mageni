###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_groove_server_detect_win.nasl 10922 2018-08-10 19:21:48Z cfischer $
#
# Microsoft Groove Server Detection
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803097");
  script_version("$Revision: 10922 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:21:48 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2013-01-10 15:20:15 +0530 (Thu, 10 Jan 2013)");
  script_name("Microsoft Groove Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"Detects the installed version of Microsoft Groove
  Server.

  The script logs in via smb, searches for Microsoft Groove Server in the
  registry and gets the version from 'ServerVersion' string in
  registry");
  exit(0);
}


include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");


if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

grooveKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:grooveKey)){
  exit(0);
}

foreach item (registry_enum_keys(key:grooveKey))
{
  grooveName = registry_get_sz(key:grooveKey + item, item:"DisplayName");
  if(!grooveName){
    continue;
  }

  if("Microsoft Office Groove Server" >< grooveName)
  {
    grooveVer = registry_get_sz(key:grooveKey + item, item:"DisplayVersion");
    if(grooveVer)
    {
      groovePath = registry_get_sz(key:grooveKey + item, item:"InstallLocation");
      if(!groovePath){
        groovePath = "Could not find the install location from registry";
      }

      set_kb_item(name:"MS/Groove-Server/Ver", value:grooveVer);
      set_kb_item(name:"MS/Groove-Server/Path", value:groovePath);
      cpe = build_cpe(value:grooveVer, exp:"^([0-9.]+)",
                           base:"cpe:/a:microsoft:groove_server:");

      if(!cpe){
        cpe = "cpe:/a:microsoft:groove_server";
      }

      register_product(cpe:cpe, location:groovePath);

      log_message(data: build_detection_report(app: grooveName,
                                              version:grooveVer, install:groovePath, cpe:cpe,
                                              concluded: grooveName));
      exit(0);
    }
  }
}
