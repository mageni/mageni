###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_grabit_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# Grabit Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800712");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Grabit Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the installed Grabit Version in Windows and
  saves the result in KB.");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Grabit Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GrabIt_is1\";
name = registry_get_sz(key:key, item:"DisplayName");

if("GrabIt" >< name)
{
  grabitVer = eregmatch(pattern:"GrabIt ([0-9.]+) Beta\ ?([0-9]+)?", string:name);
  build = eregmatch(pattern:"build ([0-9]+)", string:name);

  if(grabitVer[1] != NULL && grabitVer[2] == NULL){
    appVer = grabitVer[1];
  }
  else if(grabitVer[1] != NULL && grabitVer[2] != NULL)
  {
    # Beta version string goes here in the 2nd index value.
    appVer = grabitVer[1] + "." + grabitVer[2];
  }

  set_kb_item(name:"GrabIt/Ver", value:appVer);
  log_message(data:" version " + appVer + " was detected on the host");

  cpe = build_cpe(value:appVer, exp:"^([0-9]\.[0-9]+\.[0-9]+)", base:"cpe:/a:shemes:grabit:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  if(build[1] != NULL){
    set_kb_item(name:"GrabIt/Build/Ver", value:build[1]); # Sets for Build Version.
  }
}
