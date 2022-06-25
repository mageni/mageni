###############################################################################
# OpenVAS Vulnerability Test
# $Id: quote.nasl 4827 2016-12-21 10:31:05Z cfi $
#
# Check for Quote of the day Service (TCP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.10198");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-1999-0103");
  script_name("Check for Quote of the day Service (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 Mathieu Perrin");
  script_family("Useless services");
  script_dependencies("find_service.nasl", "find_service2.nasl");
  script_require_ports(17);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0103");

  script_tag(name:"summary", value:"The quote service (qotd) is running on this host.

  Description :

  A server listens for TCP connections on TCP port 17. Once a connection
  is established a short message is sent out the connection (and any
  data received is thrown away). The service closes the connection
  after sending the quote.");

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

if( get_port_state( port ) ) {

  p = known_service( port:port );
  if( ! p || p == "qotd" ) {
    soc = open_sock_tcp( port );
    if( soc ) {
      a = recv_line( socket:soc, length:1024 );
      if( a )
        security_message( port:port );
      close( soc );
    }
  }
}

exit( 0 );