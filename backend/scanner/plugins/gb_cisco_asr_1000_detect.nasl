###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asr_1000_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco ASR 1000 Router Detection (SNMP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105342");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-09-01 15:55:24 +0200 (Tue, 01 Sep 2015)");
  script_name("Cisco ASR 1000 Router Detection");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Cisco ASR 1000 Router");

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

# Cisco IOS Software, ASR1000 Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 15.4(1)S, RELEASE SOFTWARE (fc2)
# Cisco IOS Software, ASR1000 Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 15.4(3)S2, RELEASE SOFTWARE (fc3)
# Cisco IOS Software, ASR1000 Software (PPC_LINUX_IOSD-ADVENTERPRISEK9-M), Version 15.3(3)S1, RELEASE SOFTWARE (fc1)
if( "Cisco IOS Software, ASR1000 Software" >!< sysdesc ) exit( 0 );

set_kb_item( name:"cisco_asr_1000/installed", value:TRUE );

cpe = 'cpe:/h:cisco:asr_1000';
vers = 'unknown';

version = eregmatch( pattern:'Version ([^,]+),', string:sysdesc );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:port + "/udp", port:port, proto:"udp", service:"snmp" );

log_message( data: build_detection_report( app:"Cisco ASR1000",
                                           version:vers,
                                           install:port + "/snmp",
                                           cpe:cpe,
                                           concluded:sysdesc ),
             port:port, proto:"udp" );

exit(0);
