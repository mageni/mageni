###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_meeting_server_snmp_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Meeting Server Detection (SNMP)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140043");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-02 15:29:27 +0100 (Wed, 02 Nov 2016)");
  script_name("Cisco (Acano) Meeting Server Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Cisco Meeting Server");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

if( sysdesc !~ "^(Cisco Meeting|Acano) Server [0-9.]+$") exit( 0 );

set_kb_item( name:'cisco/meeting_server/installed', value:TRUE );

cpe = 'cpe:/a:cisco:meeting_server';
vers = 'unknown';

version = eregmatch( pattern:'^(Cisco Meeting|Acano) Server ([0-9.]+)$', string:sysdesc );
if( ! isnull( version[2] ) )
{
  vers = version[2];
  cpe += ':' + vers;
  set_kb_item( name:'cisco/meeting_server/version', value:vers );
}

register_product( cpe:cpe, location:"161/udp", port:port, service:"snmp", proto:"udp" );

report = build_detection_report( app:"Cisco (Acano) Meeting Server", version:vers, install:"161/udp", cpe:cpe, concluded:sysdesc );
log_message( port:port, data:report, proto:"udp");

exit( 0 );

