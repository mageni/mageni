###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_utorrent_detect_win.nasl 11356 2018-09-12 10:46:43Z tpassfeld $
#
# uTorrent Version Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.114007");
  script_version("$Revision: 11356 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:46:43 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-06-08 15:54:21 +0200 (Fri, 08 Jun 2018)");
  script_name("uTorrent Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of uTorrent.

  The script logs in via smb, searches for uTorrent in the registry and gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

#This is the only possible relevant registry key for uTorrent under "HKEY_CURRENT_USER"
key = "Software\Microsoft\Windows\CurrentVersion\Uninstall\uTorrent";

displayIconPath = registry_get_sz(key:key, item:"DisplayIcon", type: "HKCU");

if("uTorrent" >< displayIconPath)
{
  insloc = registry_get_sz(key:key,item:"InstallLocation", type:"HKCU");
  if(!insloc){
    insloc = "Could not find the install location from registry";
  }

  appVer = registry_get_sz(key:key,item:"DisplayVersion", type:"HKCU");
  if(appVer)
  {
    set_kb_item(name:"utorrent/win/version", value:appVer);

    cpe = build_cpe(value:appVer, exp:"^([0-9.]+)", base:"cpe:/a:bittorrent:utorrent:");
    if(isnull(cpe))
      cpe = "cpe:/a:bittorrent:utorrent";

    tmp_location = tolower(insloc);
    tmp_location = ereg_replace(pattern:"\\$", string:tmp_location, replace:'');
    set_kb_item(name:"utorrent/win/install_locations", value:tmp_location);

    register_product(cpe:cpe, location:insloc);

    log_message(data: build_detection_report(app: "uTorrent",
                                             version: appVer,
                                             install: insloc,
                                             cpe: cpe,
                                             concluded: appVer));
  }
}

exit(0);
