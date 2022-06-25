###############################################################################
# OpenVAS Vulnerability Test
#
# Check for Chargen Service (UDP)
#
# Authors:
# Mathieu Perrin <mathieu@tpfh.org>
#
# Copyright:
# Copyright (C) 1999 Mathieu Perrin
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
  script_oid("1.3.6.1.4.1.25623.1.0.108030");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-1999-0103");
  script_name("Check for Chargen Service (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 Mathieu Perrin");
  script_family("Useless services");
  script_require_udp_ports(19);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0103");

  script_tag(name:"summary", value:"The remote host is running a 'chargen' service.");

  script_tag(name:"insight", value:"When contacted, chargen responds with some random characters
  (something like all the characters in the alphabet in a row). When contacted via UDP, it
  will respond with a single UDP packet.

  The purpose of this service was to mostly to test the TCP/IP protocol by itself, to make sure that
  all the packets were arriving at their destination unaltered. It is unused these days, so it is
  suggested you disable it, as an attacker may use it to set up an attack against this host, or
  against a third party host using this host as a relay.");

  script_tag(name:"solution", value:"- Under Unix systems, comment out the 'chargen' line in /etc/inetd.conf
  and restart the inetd process

  - Under Windows systems, set the following registry keys to 0 :

  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpChargen

  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpChargen

  Then launch cmd.exe and type :

  net stop simptcp

  net start simptcp

  To restart the service.");

  script_tag(name:"impact", value:"An easy attack is 'ping-pong' in which an attacker spoofs a packet between
  two machines running chargen. This will cause them to spew characters at each other, slowing the machines
  down and saturating the network.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("misc_func.inc");
include("pingpong.inc");

port = 19;
if( ! get_udp_port_state( port ) )
  exit( 0 );

soc = open_sock_udp( port );
if( ! soc )
  exit( 0 );

data = string( "\r\n" );
send( socket:soc, data:data );
b = recv( socket:soc, length:1024 );
close( soc );

if( strlen( b ) > 255 ) {
  security_message( port:port, protocol:"udp" );
  exit( 0 );
}

exit( 99 );