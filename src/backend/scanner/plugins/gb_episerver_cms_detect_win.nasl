##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_episerver_cms_detect_win.nasl 11567 2018-09-24 08:41:14Z cfischer $
#
# EPiServer CMS Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.107341");
  script_version("$Revision: 11567 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-24 10:41:14 +0200 (Mon, 24 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-20 17:07:53 +0200 (Thu, 20 Sep 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("EPiServer CMS Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version
  of EPiServer CMS.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("secpod_smb_func.inc");

foreach key(make_list_unique("CMS", registry_enum_keys(key:"SOFTWARE\Wow6432Node\EPiServer"))) {

  key = "SOFTWARE\Wow6432Node\EPiServer\" + key;
  if(!registry_key_exists(key:key)) continue;

  appName = registry_get_sz(key:key, item:"ProductName");
  if(appName !~ "EPiServer CMS") continue;

  version = "unknown";

  foreach key2(registry_enum_keys(key:key)) {
    loc = registry_get_sz(key:key + "\" + key2, item:"InstallPath");
    ver = registry_get_sz(key:key + "\" + key2, item:"VersionName");
    if(loc && ver && ver =~ "[0-9.]+") break;
  }

  ver = eregmatch(string:ver, pattern:"^(Version )?([0-9.]+)");
  if(ver[2]) version = ver[2];

  set_kb_item(name:"EPiServer/EPiServer_CMS/Win/detected", value:TRUE);
  set_kb_item(name:"EPiServer/EPiServer_CMS/Win/Ver", value:version);

  register_and_report_cpe(app:"EPiServer CMS ", ver:version, concluded:ver[0],
    base:"cpe:/a:episerver:episerver:", expr:"^([0-9.]+)", insloc:loc);
  exit(0);
}

exit(0);