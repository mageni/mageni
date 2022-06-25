###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_snom_detect.nasl 13734 2019-02-18 11:03:47Z cfischer $
#
# Snom Detection (SIP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105168");
  script_version("$Revision: 13734 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 12:03:47 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-01-14 11:10:30 +0100 (Wed, 14 Jan 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Snom Detection (SIP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  script_tag(name:"summary", value:"The script attempts to identify an Snom devices via SIP banner");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("sip.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos['port'];
proto = infos['proto'];

banner = sip_get_banner( port:port, proto:proto );
if( ! banner || "snom" >!< banner )
  exit( 0 );

set_kb_item(name: "snom/detected", value: TRUE);
set_kb_item(name: "snom/sip/port", value: port);
set_kb_item(name: "snom/sip/" + port + "/proto", value: proto);
set_kb_item(name: "snom/sip/" + port + "/" + proto + "/concluded", value: banner);

model_version = eregmatch( pattern:'snom([0-9]*)/([^\r\n]+)', string:banner );

if( ! isnull( model_version[1] ) && model_version[1] != "" )
  set_kb_item( name:"snom/sip/" + port + "/model", value:model_version[1] );

if( ! isnull( model_version[2] ) )
  set_kb_item( name:"snom/sip/" + port + "/version", value:model_version[2] );

exit( 0 );