###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_desktop_board_bios_info_detect_win.nasl 12413 2018-11-19 11:11:31Z cfischer $
#
# Desktop Boards BIOS Information Detection for Windows
#
# Authors:
# Thomas Rotter <Thomas.Rotter@greenbone.net>
#
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96197");
  script_version("$Revision: 12413 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-04-16 10:59:11 +0100 (Thu, 16 Apr 2015)");
  script_name("Desktop Boards BIOS Information Detection for Windows");

  script_tag(name:"summary", value:"Detects the installed version of
  Desktop Boards BIOS.

  The script logs in via smb and queries for the version.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);

  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

SCRIPT_DESC = "Gather Boards BIOS related Information";

include("smb_nt.inc");
include("host_details.inc");

bios_ver = registry_get_sz(item:"BIOSVersion", key:"HARDWARE\DESCRIPTION\System\BIOS");
bios_vendor = registry_get_sz(item:"BIOSVendor", key:"HARDWARE\DESCRIPTION\System\BIOS");
base_board_ver = registry_get_sz(item:"BaseBoardVersion", key:"HARDWARE\DESCRIPTION\System\BIOS");
base_board_manu = registry_get_sz(item:"BaseBoardManufacturer", key:"HARDWARE\DESCRIPTION\System\BIOS");
base_board_prod_name = registry_get_sz(item:"BaseBoardProduct", key:"HARDWARE\DESCRIPTION\System\BIOS");
report = ""; # nb: To make openvas-nasl-lint happy...

if(bios_ver != NULL)
{
  set_kb_item(name:"DesktopBoards/BIOS/Ver", value:chomp(bios_ver));
  report += "Desktop Boards BIOS version " + bios_ver + " was detected on the host\n";
  register_host_detail(name:"BIOSVersion", value:chomp(bios_ver), desc:SCRIPT_DESC);
}

if(bios_vendor != NULL)
{
  set_kb_item(name:"DesktopBoards/BIOS/Vendor", value:chomp(bios_vendor));
  report += "Desktop Boards BIOS Vendor " + bios_vendor + " was detected on the host\n";
  register_host_detail(name:"BIOSVendor", value:chomp(bios_vendor), desc:SCRIPT_DESC);
}

if(base_board_ver)
{
  set_kb_item(name:"DesktopBoards/BaseBoard/Ver", value:chomp(base_board_ver));
  report +="Desktop Boards Base Board version " + base_board_ver + " was detected on the host\n";
  register_host_detail(name:"BaseBoardVersion", value:chomp(base_board_ver), desc:SCRIPT_DESC);
}

if(base_board_manu)
{
  set_kb_item(name:"DesktopBoards/BaseBoard/Manufacturer",
              value:chomp(base_board_manu));
  report += "Desktop Boards Base Board Manufacturer " + base_board_manu + " was detected on the host\n";
  register_host_detail(name:"BaseBoardManufacturer", value:chomp(base_board_manu), desc:SCRIPT_DESC);
}

if(base_board_prod_name)
{
  set_kb_item(name:"DesktopBoards/BaseBoard/ProdName",
              value:chomp(base_board_prod_name));
  report +="Desktop Boards Base Board Product Name " + base_board_prod_name + " was detected on the host\n";
  register_host_detail(name:"BaseBoardProduct", value:chomp(base_board_prod_name), desc:SCRIPT_DESC);
}

if(report){
  log_message(data:report);
}


