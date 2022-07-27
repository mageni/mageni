###############################################################################
# OpenVAS Vulnerability Test
# $Id: alcatel_backdoor_switch.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Alcatel OmniSwitch 7700/7800 switches backdoor
#
# Authors:
# deepquest <deepquest@code511.com>
# Modifications by rd:
# -  added ref: http://www.cert.org/advisories/CA-2002-32.html
# -  removed leftovers in the code (send(raw_string(0, 0))
# -  added the use of telnet_init()
# -  replaced open_sock_udp by open_sock_tcp()
# -  added script id
# -  attributed copyright properly to deepquest
# -  merged some ideas from Georges Dagousset <georges.dagousset@alert4web.com>
#    who wrote a duplicate of this script
#
# Copyright:
# Copyright (C) 2002 deepquest
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11170");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(6220);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2002-1272");
  script_name("Alcatel OmniSwitch 7700/7800 switches backdoor");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (c) 2002 deepquest");
  script_family("Malware");
  script_dependencies("find_service.nasl");
  script_require_ports(6778);

  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2002-32.html");

  script_tag(name:"solution", value:"Block access to port 6778/TCP or update to
  AOS 5.1.1.R02 or AOS 5.1.1.R03.");

  script_tag(name:"summary", value:"The remote host seems to be a backdoored
  Alcatel OmniSwitch 7700/7800.");

  script_tag(name:"impact", value:"An attacker can gain full access to any device
  running AOS version 5.1.1, which can result in, but is not limited to,
  unauthorized access, unauthorized monitoring, information leakage,
  or denial of service.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("telnet_func.inc");
include("misc_func.inc");

port = 6778;
p = known_service( port:port );
if( p && p != "telnet" && p != "aos" ) exit( 0 );

if( ! get_port_state( port ) ) exit( 0 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );
data = get_telnet_banner( port:port );

if( data ) {
  security_message( port:port, data:'Banner:\n' + data );
  register_service( port:port, proto:"aos" );
  exit( 0 );
}

exit( 99 );