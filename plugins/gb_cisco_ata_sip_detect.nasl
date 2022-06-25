###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco ATA Detection (SIP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_version("2020-07-31T08:46:05+0000");
  script_tag(name:"last_modification", value:"2020-08-03 11:16:30 +0000 (Mon, 03 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-12-01 14:02:18 +0100 (Thu, 01 Dec 2016)");

  script_name("Cisco ATA Detection (SIP)");

  script_tag(name:"summary", value:"SIP based detection of Cisco Analog Telephone Adapter (ATA) devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("sip.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port  = infos["port"];
proto = infos["proto"];

banner = sip_get_banner( port:port, proto:proto );
if( ! banner || banner !~ "^Cisco[- ]ATA ?[0-9]{3}")
  exit( 0 );

set_kb_item( name:"cisco/ata/detected", value:TRUE );
set_kb_item( name:"cisco/ata/sip/detected", value:TRUE );
set_kb_item( name:"cisco/ata/sip/port", value:port );
set_kb_item( name:"cisco/ata/sip/" + port + "/proto", value:proto );
set_kb_item( name:"cisco/ata/sip/" + port + "/concluded", value:banner );

version = "unknown";
model = "unknown";

# Cisco-ATA187/9.2.3
# Cisco-ATA191-MPP/11-1-0MSR3-9
# Cisco ATA 186  v3.1.0 atasip (040211A)
mod = eregmatch( pattern:"Cisco[- ]ATA ?([0-9]{3})", string:banner );
if( ! isnull( mod[1] ) )
  model = mod[1];

vers = eregmatch( pattern:"Cisco[^v/]+[/v]([0-9A-Z.-]+)", string:banner );
if( ! isnull( vers[1] ) )
  version = str_replace( string:vers[1], find:"-", replace:"."); # version is not reliable

set_kb_item( name:"cisco/ata/sip/" + port + "/model", value:model );
set_kb_item( name:"cisco/ata/sip/" + port + "/version", value:version );

exit( 0 );
