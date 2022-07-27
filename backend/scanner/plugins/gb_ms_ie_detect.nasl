###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_detect.nasl 11086 2018-08-23 06:43:53Z santu $
#
# Microsoft Internet Explorer Version Detection (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800209");
  script_version("$Revision: 11086 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-23 08:43:53 +0200 (Thu, 23 Aug 2018) $");
  script_tag(name:"creation_date", value:"2008-12-19 13:40:09 +0100 (Fri, 19 Dec 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Internet Explorer Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  Microsoft Internet Explorer.

  The script logs in via smb, detects the version of Microsoft Internet Explorer
  on remote host and sets the KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "smb_registry_access.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Internet Explorer")){
  exit(0);
}

if(!ver = registry_get_sz(item:"svcVersion",
                        key:"SOFTWARE\Microsoft\Internet Explorer")){
  ver = registry_get_sz(item:"Version",
                        key:"SOFTWARE\Microsoft\Internet Explorer");
}

exePath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\IEXPLORE.EXE", item:"Path") - ";";

if(ver != NULL)
{
  set_kb_item(name:"MS/IE/Version", value:ver);
  set_kb_item(name:"MS/IE/Installed", value:TRUE);
  set_kb_item( name:"MS/IE_or_EDGE/Installed", value:TRUE );
  register_and_report_cpe( app:"Microsoft Internet Explorer", ver:ver, base:"cpe:/a:microsoft:ie:", expr:"^([0-9.]+)", insloc:exePath );
}

if(exePath != NULL && ver ==NULL)
{
  ieVer = fetch_file_version(sysPath:exePath, file_name:"iexplore.exe");

  if(ieVer)
  {
    set_kb_item(name:"MS/IE/EXE/Ver", value:ieVer);
    set_kb_item(name:"MS/IE/Installed", value:TRUE);
    set_kb_item( name:"MS/IE_or_EDGE/Installed", value:TRUE );
    register_and_report_cpe( app:"Microsoft Internet Explorer", ver:ieVer, base:"cpe:/a:microsoft:ie:", expr:"^([0-9.]+)", insloc:exePath );
  }
}
