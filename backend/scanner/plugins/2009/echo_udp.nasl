###############################################################################
# OpenVAS Vulnerability Test
# $Id: echo_udp.nasl 8236 2017-12-22 10:28:23Z cfischer $
#
# Check for echo Service (UDP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.315147");
  script_version("$Revision: 8236 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 11:28:23 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-24 15:43:44 +0100 (Tue, 24 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #script_cve_id("CVE-1999-0635");
  script_name("Check for echo Service (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Useless services");
  script_require_udp_ports("Services/udp/echo", 7);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0635");

  tag_summary = "An echo Service is running at this Host.

  The echo service is an Internet protocol defined in RFC 862. It was
  originally proposed for testing and measurement of round-trip times in IP
  networks. While still available on most UNIX-like operating systems, testing
  and measurement is now performed with the Internet Control Message Protocol
  (ICMP), using the applications ping and traceroute.";

  tag_solution = "Disable the echo Service.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");

port = get_kb_item( "Services/udp/echo" );
if( ! port ) port = 7;
if( ! get_udp_port_state( port ) ) exit( 0 );

soc = open_sock_udp( port );
if( ! soc ) exit( 0 );

echo_string = "OpenVAS-Echo-Test";

send( socket:soc, data:echo_string );
buf = recv( socket:soc, length:4096 );
close( soc );

if( buf == echo_string ) {
  register_service( port:port, proto:"echo", ipproto:"udp" );
  security_message( port:port, protocol:"udp" );
  exit( 0 );
}

exit( 99 );
