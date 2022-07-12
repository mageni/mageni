###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_measuresoft_scadapro_server_detect.nasl 11420 2018-09-17 06:33:13Z cfischer $
#
# Measuresoft ScadaPro Server Detection
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803948");
  script_version("$Revision: 11420 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 08:33:13 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-10-01 17:59:16 +0530 (Tue, 01 Oct 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Measuresoft ScadaPro Server Detection");

  script_tag(name:"summary", value:"Detects the installed version of Measuresoft ScadaPro Server.

  The script logs in via smb, searches for Measuresoft ScadaPro Server in the
  registry and gets the version from 'VersionID' string in registry.");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

scadaproKey = "SOFTWARE\Measuresoft\SCADAPRO";
if(!registry_key_exists(key:scadaproKey)){
  exit(0);
}

verKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\mainmenuServer";
if(!registry_key_exists(key:verKey)){
  exit(0);
}

scadaprosvrVer = registry_get_sz(key:verKey, item:"VersionID");
if(!scadaprosvrVer){
  exit(0);
}

insloc = registry_get_sz(key:scadaproKey, item:"Root:");
if(!insloc){
  insloc = "Could not find the install location from registry";
}


set_kb_item(name:"ScadaProServer/Win/Ver", value:scadaprosvrVer);

cpe = build_cpe(value:scadaprosvrVer, exp:"^([0-9.]+)", base:"cpe:/a:measuresoft:scadapro_server:");
if(isnull(cpe))
  cpe = "cpe:/a:measuresoft:scadapro_server";

register_product(cpe:cpe, location:insloc);

log_message(data: build_detection_report(app:"Measuresoft ScadaPro Server ",
                                         version:scadaprosvrVer,
                                         install:insloc,
                                         cpe:cpe,
                                         concluded:scadaprosvrVer));
