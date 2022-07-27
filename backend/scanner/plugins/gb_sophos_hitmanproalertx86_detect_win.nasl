##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sophos_hitmanproalertx86_detect_win.nasl 12195 2018-11-02 08:08:23Z mmartin $
#
# Sophos HitmanPro.Alert x86 Version Detection (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH, http//www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107359");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12195 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-02 09:08:23 +0100 (Fri, 02 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-01 14:20:47 +0100 (Thu, 01 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sophos HitmanPro.Alert x86 Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed version
  of Sophos HitmanPro.Alert for Windows.");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

foreach key(make_list_unique("HitmanPro.Alert",
  registry_enum_keys(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))){

  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + key;
  if(!registry_key_exists(key:key)) continue;

  appName = registry_get_sz(key:key, item:"DisplayName");
  if(appName !~ "HitmanPro.Alert") continue;
  loc = registry_get_sz(key:key, item:"InstallLocation");
  ver = registry_get_sz(key:key, item:"DisplayVersion");

  set_kb_item(name:"Sophos/HitmanPro.Alert/Win/detected", value:TRUE);
  set_kb_item(name:"Sophos/HitmanPro.Alert/Win/Ver", value:ver);

  register_and_report_cpe(app: "Sophos " + appName , ver:ver,
    base:"cpe:/a:sophos:hitmanpro.alert:", expr:"^([0-9.a-z-]+)", insloc:loc);
  exit(0);
}
exit(0);
