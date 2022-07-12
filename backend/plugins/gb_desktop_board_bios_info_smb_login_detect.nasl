# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96197");
  script_version("2021-06-07T11:59:32+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-06-08 10:08:36 +0000 (Tue, 08 Jun 2021)");
  script_tag(name:"creation_date", value:"2015-04-16 10:59:11 +0100 (Thu, 16 Apr 2015)");
  script_name("BIOS and Hardware Information Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"SMB login-based gathering of various BIOS and Hardware related
  information.");

  script_tag(name:"vuldetect", value:"Logs in via SMB and queries the BIOS and Hardware related information
  from the Windows registry.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");

SCRIPT_DESC = "BIOS and Hardware Information Detection (Windows SMB Login)";

bios_ver = registry_get_sz(item:"BIOSVersion", key:"HARDWARE\DESCRIPTION\System\BIOS");
bios_ver = chomp(bios_ver);

bios_vendor = registry_get_sz(item:"BIOSVendor", key:"HARDWARE\DESCRIPTION\System\BIOS");
bios_vendor = chomp(bios_vendor);

base_board_ver = registry_get_sz(item:"BaseBoardVersion", key:"HARDWARE\DESCRIPTION\System\BIOS");
base_board_ver = chomp(base_board_ver);

base_board_manu = registry_get_sz(item:"BaseBoardManufacturer", key:"HARDWARE\DESCRIPTION\System\BIOS");
base_board_manu = chomp(base_board_manu);

base_board_prod_name = registry_get_sz(item:"BaseBoardProduct", key:"HARDWARE\DESCRIPTION\System\BIOS");
base_board_prod_name = chomp(base_board_prod_name);

report = ""; # nb: To make openvas-nasl-lint happy...

if(bios_ver && strlen(bios_ver) > 0) {
  set_kb_item(name:"DesktopBoards/BIOS/Ver", value:bios_ver);
  report += "BIOS version: " + bios_ver + '\n';
  register_host_detail(name:"BIOSVersion", value:bios_ver, desc:SCRIPT_DESC);
}

if(bios_vendor && strlen(bios_vendor) > 0) {
  set_kb_item(name:"DesktopBoards/BIOS/Vendor", value:bios_vendor);
  report += "BIOS Vendor: " + bios_vendor + '\n';
  register_host_detail(name:"BIOSVendor", value:bios_vendor, desc:SCRIPT_DESC);
}

if(base_board_ver && strlen(base_board_ver) > 0) {
  set_kb_item(name:"DesktopBoards/BaseBoard/Ver", value:base_board_ver);
  report += "Base Board version: " + base_board_ver + '\n';
  register_host_detail(name:"BaseBoardVersion", value:base_board_ver, desc:SCRIPT_DESC);
}

if(base_board_manu && strlen(base_board_manu) > 0) {
  set_kb_item(name:"DesktopBoards/BaseBoard/Manufacturer", value:base_board_manu);
  report += "Base Board Manufacturer: " + base_board_manu + '\n';
  register_host_detail(name:"BaseBoardManufacturer", value:base_board_manu, desc:SCRIPT_DESC);
}

if(base_board_prod_name && strlen(base_board_prod_name) > 0) {
  set_kb_item(name:"DesktopBoards/BaseBoard/ProdName", value:base_board_prod_name);
  report += "Base Board Product Name: " + base_board_prod_name + '\n';
  register_host_detail(name:"BaseBoardProduct", value:base_board_prod_name, desc:SCRIPT_DESC);
}

if(report)
  log_message(port:0, data:chomp(report));

exit(0);