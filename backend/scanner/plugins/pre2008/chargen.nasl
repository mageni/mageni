###############################################################################
# OpenVAS Vulnerability Test
# $Id: chargen.nasl 4827 2016-12-21 10:31:05Z cfi $
#
# Check for Chargen Service (TCP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.10043");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-1999-0103");
  script_name("Check for Chargen Service (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 Mathieu Perrin");
  script_family("Useless services");
  script_dependencies("find_service.nasl");
  script_require_ports(19);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0103");

  script_tag(name:"summary", value:"The remote host is running a 'chargen' service.

  Description :

  When contacted, chargen responds with some random characters (something
  like all the characters in the alphabet in a row). When contacted via TCP,
  it will continue spewing characters until the client closes the connection.

  The purpose of this service was to mostly to test the TCP/IP protocol
  by itself, to make sure that all the packets were arriving at their
  destination unaltered. It is unused these days, so it is suggested
  you disable it, as an attacker may use it to set up an attack against
  this host, or against a third party host using this host as a relay.");

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
  two machines running chargen. This will cause them to spew characters at
  each other, slowing the machines down and saturating the network.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("misc_func.inc");
include("pingpong.inc");

port = 19;

if( get_port_state( port ) ) {

  p = known_service( port:port );
  if( ! p || p == "chargen" ) {
    soc = open_sock_tcp( port );
    if( soc ) {
      a = recv( socket:soc, length:255, min:255 );
      if( strlen( a ) > 255 )
        security_message( port:port );
      close( soc );
    }
  }
}

exit( 0 );