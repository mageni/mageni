###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pfsense_detect_snmp.nasl 7769 2017-11-15 10:07:45Z asteins $
#
# pfSense Detection (SNMP)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112117");
  script_version("$Revision: 7769 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-15 11:07:45 +0100 (Wed, 15 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-10 13:04:05 +0100 (Fri, 10 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("pfSense Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of pfSense.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("snmp_func.inc");
include("misc_func.inc");

port = get_snmp_port( default:161 );

if( ! sysdesc = get_snmp_sysdesc(port:port ) ) exit ( 0 );

if ( "pfSense" >< sysdesc ) {
  set_kb_item( name:"pfsense/installed", value:TRUE );
  set_kb_item( name:"pfsense/snmp/installed", value:TRUE );
  set_kb_item( name:"pfsense/snmp/port", value:port );

  version = "unknown";
  vers = eregmatch( pattern:"^pfSense .* ([0-9.]+)-RELEASE .* FreeBSD", string:sysdesc );

  if( vers[1] ) {
    version = vers[1];
  }
  set_kb_item( name:"pfsense/snmp/" + port + "/version", value:version );
  set_kb_item( name:"pfsense/snmp/" + port + "/concluded", value:sysdesc);
}

exit( 0 );
