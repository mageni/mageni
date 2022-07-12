###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rdp_version_detect_win.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Microsoft Remote Desktop Protocol Version Detection (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808281");
  script_version("$Revision: 11885 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-03 17:52:03 +0530 (Wed, 03 Aug 2016)");
  script_name("Microsoft Remote Desktop Protocol Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  Remote Desktop Protocol.

  The script logs in via smb and check the version of mstscax.dll file.");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

rdpVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mstscax.dll");

if(rdpVer) {

  rdpPath = sysPath + "\System32\Mstscax.dll";
  set_kb_item(name:"remote/desktop/protocol/Win/Installed", value:TRUE);
  set_kb_item(name:"remote/desktop/protocol/Win/Ver", value:rdpVer);

  register_and_report_cpe( app:"Microsoft Remote Desktop Protocol", ver:rdpVer, base:"cpe:/a:microsoft:rdp:", expr:"^([0-9.]+)", insloc:rdpPath );
}
