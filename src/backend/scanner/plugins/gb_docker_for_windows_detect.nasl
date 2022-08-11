##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_docker_for_windows_detect.nasl 11288 2018-09-07 10:13:15Z mmartin $
#
# Docker for Windows Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.107337");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11288 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 12:13:15 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-06 14:43:30 +0200 (Thu, 06 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Docker for Windows Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed version
  of Docker for Windows.");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("secpod_smb_func.inc");

foreach key(make_list_unique("Docker for Windows",
  registry_enum_keys(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))){

  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + key;
  if(!registry_key_exists(key:key)) continue;

  appName = registry_get_sz(key:key, item:"DisplayName");
  if(appName !~ "Docker for Windows") continue;
  Loc = registry_get_sz(key:key, item:"InstallLocation");
  Chan = registry_get_sz(key:key, item:"ChannelName");
  Ver = registry_get_sz(key:key, item:"DisplayVersion");

  set_kb_item(name:"Docker/Docker_for_Windows/Win/Chan", value: Chan);
  set_kb_item(name:"Docker/Docker_for_Windows/Win/detected", value:TRUE);
  set_kb_item(name:"Docker/Docker_for_Windows/Win/Ver", value:Ver);

  register_and_report_cpe(app:"Docker for Windows " +Chan, ver:Ver,
    base:"cpe:/a:docker:docker_for_windows:", expr:"^([0-9.a-z-]+)", insloc:Loc);
  exit(0);
}
exit(0);
