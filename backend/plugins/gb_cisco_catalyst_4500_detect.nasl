###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_catalyst_4500_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Catalyst 4500 Detection (SNMP)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105379");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-09-21 13:29:25 +0200 (Mon, 21 Sep 2015)");
  script_name("Cisco Catalyst 4500 Detection");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Cisco Catalyst 4500");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
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

# Cisco IOS Software, Catalyst 4500 L3 Switch Software (cat4500-ENTSERVICESK9-M), Version 15.0(2)SG7, RELEASE SOFTWARE (fc2)
# Cisco IOS Software, Catalyst 4500 L3 Switch Software (cat4500-ENTSERVICES-M), Version 12.2(31)SGA4, RELEASE SOFTWARE (fc1)
# Cisco IOS Software, IOS-XE Software, Catalyst 4500 L3 Switch Software (cat4500e-UNIVERSAL-M), Version 03.04.04.SG RELEASE SOFTWARE (fc2)
# Cisco IOS Software, IOS-XE Software, Catalyst 4500 L3 Switch Software (cat4500e-UNIVERSAL-M), Version 03.03.02.SG RELEASE SOFTWARE (fc1)
if( "Catalyst 4500 L3" >!< sysdesc ) exit( 0 );

set_kb_item( name:"cisco_catalyst_4500/installed", value:TRUE );

cpe = 'cpe:/h:cisco:catalyst_4500';
vers = 'unknown';

if( "IOS-XE" >< sysdesc )
{
  set_kb_item( name:"cisco_catalyst_4500/IOS-XE", value:TRUE );
  version = eregmatch( pattern:'Version ([^ ]+)', string:sysdesc );
}
else
  version = eregmatch( pattern:'Version ([^,]+),', string:sysdesc );

if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:port + "/udp", port:port, proto:"udp", service:"snmp" );

log_message( data: build_detection_report( app:"Cisco Catalyst 4500",
                                           version:vers,
                                           install:port + "/snmp",
                                           cpe:cpe,
                                           concluded:sysdesc ),
             port:port, proto:"udp" );

exit(0);
