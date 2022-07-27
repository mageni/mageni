###############################################################################
# OpenVAS Vulnerability Test
# $Id: quote_udp.nasl 14336 2019-03-19 14:53:10Z mmartin $
#
# Check for Quote of the day Service (UDP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108029");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-1999-0103");
  script_name("Check for Quote of the day Service (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 Mathieu Perrin");
  script_family("Useless services");
  script_require_udp_ports(17);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0103");

  script_tag(name:"summary", value:"The quote service (qotd) is running on this host.

  Description :

  A server listens for UDP datagrams on UDP port 17.
  When a datagram is received, an answering datagram is sent containing
  a quote (the data in the received datagram is ignored).");
  script_tag(name:"solution", value:"- Under Unix systems, comment out the 'qotd' line in /etc/inetd.conf
  and restart the inetd process

  - Under Windows systems, set the following registry keys to 0 :
    HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpQotd
    HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpQotd

  Then launch cmd.exe and type :

    net stop simptcp
    net start simptcp

  To restart the service.");
  script_tag(name:"impact", value:"An easy attack is 'pingpong' which IP spoofs a packet between two machines
  running qotd. This will cause them to spew characters at each other,
  slowing the machines down and saturating the network.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");

port = 17;

if( get_udp_port_state( port ) ) {
  udpsoc = open_sock_udp( port );
  send( socket:udpsoc, data:'\r\n' );
  b = recv( socket:udpsoc, length:1024 );
  if( b ) security_message( port:port, protocol:"udp" );
  close( udpsoc );
}

exit( 0 );
