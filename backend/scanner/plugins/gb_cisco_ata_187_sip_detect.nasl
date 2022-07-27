###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ata_187_sip_detect.nasl 13734 2019-02-18 11:03:47Z cfischer $
#
# Cisco ATA 187 Detection (SIP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140085");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13734 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 12:03:47 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-12-01 14:02:18 +0100 (Thu, 01 Dec 2016)");
  script_name("Cisco ATA 187 Detection (SIP)");

  script_tag(name:"summary", value:"This script performs SIP based detection of Cisco ATA 187 devices");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  exit(0);
}

include("host_details.inc");
include("sip.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port  = infos['port'];
proto = infos['proto'];

banner = sip_get_banner( port:port, proto:proto );
if( ! banner || "Cisco-ATA187/" >!< banner ) exit( 0 );

cpe = 'cpe:/o:cisco:ata_187_analog_telephone_adaptor_firmware';
set_kb_item( name:"cisco/ata187/detected", value:TRUE);
vers = 'unknown';

# Cisco-ATA187/9.2.3
v = eregmatch( pattern:'Cisco-ATA187/(9[0-9.]+)', string:banner );

if( ! isnull( v[1] ) ) {
  vers = v[1]; # version is not reliable
  cpe += ':' + vers;
}

location = port + "/" + proto;

register_product( cpe:cpe, location:location, port:port, service:"sip", proto:proto );

log_message( port:port, data:build_detection_report( app:"Cisco ATA 187", version:vers, install:location, cpe:cpe, concluded:v[0] ), proto:proto );
exit( 0 );