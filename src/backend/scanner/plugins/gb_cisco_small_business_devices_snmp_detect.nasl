###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_small_business_devices_snmp_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Small Business Device Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105767");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-16 09:06:38 +0200 (Thu, 16 Jun 2016)");
  script_name("Cisco Small Business Device Detection");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Cisco Small Business devices");

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

# Linux, Cisco Small Business RV130 (RV130), Version 1.0.2.7
# Linux, Cisco Small Business RV325, Version 1.1.1.06 Fri Dec 6 11:10:41 CST 2013
# Linux, Cisco Small Business ISA550(ISA550-K9), Version 1.0.3 Wed May 23 18:50:29 CST 2012
# Linux, Cisco Small Business WAP4410N-A, Version 2.0.6.1
# Linux 2.6.21.5-lvl7-dev, Cisco Small Business WAP121 (WAP121-E-K9), Version 1.0.5.3 Thu Sep 11 03:49:18 EDT 2014
# Linux, Cisco Small Business RV320, Version 1.2.1.14 Thu Aug 13 14:25:16 CST 2015
if( sysdesc !~ "^Linux[^,]*, Cisco Small Business" ) exit( 0 );

cpe = 'cpe:/h:cisco:small_business';
vers = 'unknown';

m = eregmatch( pattern:'Cisco Small Business ([a-zA-z]+[^, ]+)', string:sysdesc );
if( ! isnull( m[1] ) )
{
  model = m[1];
  set_kb_item( name:'cisco/small_business/model', value:model );
}

version = eregmatch( pattern:', Version ([0-9]+[^ \r\n]+)', string:sysdesc );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
  set_kb_item( name:'cisco/small_business/version', value:vers );
}

register_product( cpe:cpe, location:port + "/udp", port:port, service:"snmp", proto:"udp" );

report = build_detection_report( app:"Cisco Small Business " + model, version:vers, install:port + "/udp", cpe:cpe, concluded:sysdesc );
log_message( port:port, data:report, proto:"udp");

exit( 0 );
