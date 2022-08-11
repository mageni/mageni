# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108682");
  script_version("2019-10-22T09:18:17+0000");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2019-10-22 09:18:17 +0000 (Tue, 22 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-22 08:02:28 +0000 (Tue, 22 Oct 2019)");
  script_name("PPTP Service OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("pptp_detect.nasl");
  script_mandatory_keys("pptp/vendor_string/detected");

  script_tag(name:"summary", value:"This script performs PPTP service based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

SCRIPT_DESC = "PPTP Service OS Identification";
BANNER_TYPE = "PPTP Service banner";

port = get_port_for_service( default:1723, proto:"pptp" );

if( ! banner = get_kb_item( "pptp/" + port + "/vendor_string" ) )
  exit( 0 );

# Vendor: linux
if( tolower( banner ) == "linux" ) {
  register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# Vendor: MikroTik
else if( "MikroTik" >< banner ) {
  register_and_report_os( os:"Mikrotik Router OS", cpe:"cpe:/o:mikrotik:routeros", banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# Vendor: FreeBSD MPD
# Vendor: FreeBSD/NIW Solutions
else if( "FreeBSD" >< banner ) {
  register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# Vendor: DrayTek
else if( "DrayTek" >< banner ) {
  register_and_report_os( os:"DrayTek Unknown Router Firmware", cpe:"cpe:/o:draytek:unknown_router_firmware", banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# Vendor: Microsoft
else if( "Microsoft" >< banner ) {
  register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"windows" );
}

# Vendor: Fortinet pptp
else if( "Fortinet" >< banner ) {
  register_and_report_os( os:"FortiOS", cpe:"cpe:/o:fortinet:fortios", banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# Vendor: BUFFALO
else if( "BUFFALO" >< banner ) {
  register_and_report_os( os:"Buffalo Unknown Router Firmware", cpe:"cpe:/o:buffalotech:unknown_router_firmware", banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# Vendor: TP-LINK
else if( "TP-LINK" >< banner ) {
  register_and_report_os( os:"TP-LINK Unknown Router Firmware", cpe:"cpe:/o:tp-link:unknown_router_firmware", banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# Vendor: Cisco Systems, Inc.
# Vendor: Cisco Systems
else if( "Cisco" >< banner ) {
  register_and_report_os( os:"Cisco IOS", cpe:"cpe:/o:cisco:ios", banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# Vendor: Mac OS X, Apple Computer, Inc
else if( "Mac OS X" >< banner || "Apple Computer" >< banner ) {
  register_and_report_os( os:"Mac OS X / macOS", cpe:"cpe:/o:apple:mac_os_x", banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# Vendor: ZyXEL Communication Corp.
else if( "ZyXEL" >< banner ) {
  register_and_report_os( os:"ZyXEL Unknown Router Firmware", cpe:"cpe:/o:zyxel:unknown_router_firmware", banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# Vendor: D-Link
else if( "D-Link" >< banner ) {
  register_and_report_os( os:"D-Link Unknown Router Firmware", cpe:"cpe:/o:d-link:unknown_router_firmware", banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# Vendor: Aruba
else if( "Aruba" >< banner ) {
  register_and_report_os( os:"Aruba Networks ArubaOS", cpe:"cpe:/o:arubanetworks:arubaos", banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# Currently unknown:
# Vendor: cananian
# Vendor: YAMAHA Corporation
# Vendor: nmap
# Vendor: Freebox
# Vendor: AMIT
# Vendor: THOMSON
# Vendor: Jungo
# Vendor: UTT_OID_8874
# Vendor: Router
# Vendor: ALCATEL
# Vendor: Clavister
# Vendor: MoretonBay -> Could be PoPToP server running only on Linux
# Vendor: Allworx Server VPN
# Vendor: innovaphone
# Vendor: BinTec (HG4100)
# Vendor: NTT
# Vendor: Router
# Vendor: Sarian, PPTP
# Vendor: IIJ
# Vendor: MN128-SOHO-IB3
# Vendor: xxxxxx
# Vendor: PPTP
# Vendor: netopia
# Vendor: FWvendor pptp
# Vendor: MR504DV
# Vendor: Red-Giant Network Operating System
# Vendor: Ruijie General Operation System

else {
  # nb: Setting the runs_key to unixoide makes sure that we still schedule NVTs using Host/runs_unixoide as a fallback
  register_and_report_os( os:banner, banner_type:BANNER_TYPE, banner:banner, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );

  if( banner != "xxxxxx" && banner != "Router" && banner != "PPTP" )
    register_unknown_os_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"pptp_banner", port:port );
}

exit( 0 );
