###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_wpp_enterprise_library_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# Microsoft Windows Patterns & Practices EntLib Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900956");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Microsoft Windows Patterns & Practices EntLib Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the installed version of Microsoft Windows
  Patterns & Practices Enterprise Library and saves the version in KB.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Microsoft Windows Patterns and Practices EntLib Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  entlibName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Enterprise Library" >< entlibName)
  {
    entlibVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!isnull(entlibVer)){
      set_kb_item(name:"MS/WPP/EntLib/Ver", value:entlibVer);
      log_message(data:"Microsoft Windows Patterns & Practices Enterprise "+
                         "Library version " + entlibVer + " was detected on the host");

      cpe = build_cpe(value:entlibVer, exp:"^([0-9]\.[0-9])", base:"cpe:/a:microsoft:enterprise_library:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    }
  }
}
