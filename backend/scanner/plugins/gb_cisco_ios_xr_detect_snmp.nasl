###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xr_detect_snmp.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco IOS XR Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105079");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-09-04 09:48:32 +0200 (Thu, 04 Sep 2014)");
  script_name("Cisco IOS XR Detection");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Cisco IOS XR.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

source = "snmp";

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

# Cisco IOS XR Software (Cisco 12816/PRP), Version 4.3.2[Default] Copyright (c) 2014 by Cisco Systems, Inc.
# Cisco IOS XR Software (Cisco ASR9K Series), Version 5.1.1[Default]  Copyright (c) 2014 by Cisco Systems, Inc.
# Cisco IOS XR Software (Cisco 12404/PRP), Version 3.6.0[00] Copyright (c) 2007 by Cisco Systems, Inc.
if( "Cisco IOS XR" >!< sysdesc )exit( 0 );

set_kb_item( name:"cisco_ios_xr/detected", value:TRUE );

version = eregmatch( pattern:'Cisco IOS XR Software.*Version ([0-9.]+)', string:sysdesc );
if( isnull( version[1] ) ) exit( 0 );

cpe = 'cpe:/o:cisco:ios_xr:' + version[1];

set_kb_item( name:"cisco_ios_xr/" + source + "/version", value:version[1] );

set_kb_item(name:"Host/OS/SNMP", value:"Cisco IOS XR");
set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

type = eregmatch( pattern:'Cisco IOS XR Software \\(Cisco ([^)]+)\\)', string:sysdesc );
if( ! isnull( type[1] ) )
{
  set_kb_item( name:"cisco_ios_xr/" + source + "/model", value:type[1] );
}

report = 'The remote host is running IOS XR ';

if( type[1] )
  report += '(' + type[1]  + ') ';

report += version[1] + '\nCPE: '+ cpe + '\nConcluded: ' + sysdesc + '\n';

log_message(data:report, port:port, proto:'udp');

exit( 0 );

