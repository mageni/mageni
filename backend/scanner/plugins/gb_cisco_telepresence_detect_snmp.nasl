###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_telepresence_detect_snmp.nasl 12420 2018-11-19 13:50:15Z cfischer $
#
# Cisco TelePresence Detection (SNMP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103890");
  script_version("$Revision: 12420 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 14:50:15 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-01-27 13:32:54 +0100 (Mon, 27 Jan 2014)");
  script_name("Cisco TelePresence Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if( !sysdesc || sysdesc !~ '(Cisco|TANDBERG) Codec' || "MCU:" >!< sysdesc || "SoftW:" >!< sysdesc ) exit (0);

typ = 'unknown';
version = 'unknown';

t = eregmatch( pattern:'MCU: ([^\r\n]+)', string:sysdesc );
if( ! isnull( t[1] ) )
  typ = t[1];

s = eregmatch( pattern:'SoftW: ([^\r\n]+)', string:sysdesc );
if( ! isnull( s[1] ) )
  version = s[1];

set_kb_item( name:"cisco/telepresence/typ", value:typ );
set_kb_item( name:"cisco/telepresence/version", value:version  );

cpe = 'cpe:/a:cisco:telepresence_mcu_mse_series_software:' + tolower ( version );

register_product( cpe:cpe, location:port + "/udp", port:port, proto:"udp", service:"snmp");
log_message( data: build_detection_report( app: typ,
                                           version: version,
                                           install: port + "/udp",
                                           cpe: cpe,
                                           concluded:sysdesc ),
             port: port, proto: "udp" );

exit (0);
