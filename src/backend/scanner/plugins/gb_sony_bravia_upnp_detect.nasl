# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117234");
  script_version("2021-02-25T16:18:00+0000");
  script_tag(name:"last_modification", value:"2021-02-26 11:25:03 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-25 15:17:04 +0000 (Thu, 25 Feb 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sony BRAVIA TV Detection (UPnP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_upnp_detect.nasl");
  script_mandatory_keys("upnp/identified");

  script_tag(name:"summary", value:"UPnP based detection of Sony BRAVIA TV devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = service_get_port( default:1900, ipproto:"udp", proto:"upnp" );
banner = get_kb_item( "upnp/" + port + "/banner" );
if( ! banner || "USN:" >!< banner )
  exit( 0 );

#USN: uuid:NFANDROID2-PRV-SONYANDROIDTV2019M3-SONY=BRAVIA=4K=UR2-10378-D12E1A6B9D5AD9CB794EE2EA410A6BE255DB4579C662E823E283C39CFB94DC38::upnp:rootdevice
if( concl = egrep( pattern:"^USN:.+SONY.+BRAVIA", string:banner, icase:FALSE ) ) {

  concl = chomp( concl );
  install = port + "/udp";
  version = "unknown";
  cpe = "cpe:/h:sony:bravia";

  set_kb_item( name:"sony/bravia_tv/detected", value:TRUE );
  set_kb_item( name:"sony/bravia_tv/upnp/detected", value:TRUE );

  register_product( cpe:cpe, location:install, port:port, service:"upnp", proto:"udp" );

  log_message( port:port, proto:"udp", data:build_detection_report( app:"Sony BRAVIA TV", version:version, install:install, cpe:cpe, concluded:concl ) );
}

exit( 0 );
