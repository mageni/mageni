###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_vcs_detect.nasl 13734 2019-02-18 11:03:47Z cfischer $
#
# Cisco TelePresence Video Communication Server Detection (SIP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105332");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13734 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 12:03:47 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-08-27 14:44:28 +0200 (Thu, 27 Aug 2015)");
  script_name("Cisco TelePresence Video Communication Server Detection (SIP)");

  script_tag(name:"summary", value:"The script sends a connection
  request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  exit(0);
}

include("host_details.inc");
include("sip.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos['port'];
proto = infos['proto'];

if( ! banner = sip_get_banner( port:port, proto: proto ) ) exit( 0 );

# https://supportforums.cisco.com/document/12270151/sip-user-agents-ua-telepresence
valid_devices = make_list( 'TANDBERG/4132', 'TANDBERG/4131', 'TANDBERG/4130', 'TANDBERG/4129', 'TANDBERG/4120', 'TANDBERG/4103', 'TANDBERG/4102', 'TANDBERG/4352', 'TANDBERG/4481' );

if( "TANDBERG/4" >!< banner ) exit( 0 );

foreach device ( valid_devices )
{
  if( device >< banner )
  {
    device_is_valid = TRUE;
    break;
  }
}

if( ! device_is_valid ) exit( 0 );

vers = 'unknown';
model = 'unknown';
cpe = 'cpe:/a:cisco:telepresence_video_communication_server_software';

version = eregmatch( pattern:'TANDBERG/([^ ]+) \\(X([^-)]+)\\)', string:banner );

if( ! isnull( version[1] ) ) {
  model = version[1];
  set_kb_item( name:"cisco_vcs/sip/model", value:model );
}

if( ! isnull( version[2] ) ) {
  vers = version[2];
  cpe += ':' + vers;
  set_kb_item( name:"cisco_vcs/sip/version", value:vers );
}

set_kb_item( name:"cisco_vcs/installed",value:TRUE );

location = port + "/" + proto;

register_product(cpe: cpe, port: port, location: location, service: "sip", proto: proto);

log_message( data: build_detection_report( app:"Cisco TelePresence Video Communication Server (" + model + ")",
                                           version:vers,
                                           install:location,
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:port, proto:proto );

exit(0);