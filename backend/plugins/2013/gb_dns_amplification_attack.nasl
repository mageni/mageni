###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dns_amplification_attack.nasl 12025 2018-10-23 08:16:52Z mmartin $
#
# DNS Amplification Attack
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103718");
  script_version("$Revision: 12025 $");
  script_cve_id("CVE-2006-0987");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 10:16:52 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-05-28 11:31:19 +0200 (Tue, 28 May 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("DNS Amplification Attacks");
  script_category(ACT_ATTACK);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("dns_server.nasl", "global_settings.nasl");
  script_require_udp_ports("Services/udp/domain", 53);
  script_mandatory_keys("DNS/identified");
  script_exclude_keys("keys/islocalhost", "keys/islocalnet", "keys/is_private_addr");

  script_xref(name:"URL", value:"http://www.us-cert.gov/ncas/alerts/TA13-088A");
  script_xref(name:"URL", value:"http://www.isotf.org/news/DNS-Amplification-Attacks.pdf");

  script_tag(name:"insight", value:"A Domain Name Server (DNS)Amplification attack is a popular form of
  Distributed Denial of Service (DDoS) that relies on the use of publicly
  accessible open recursive DNS servers to overwhelm a victim system with DNS
  response traffic.

  The basic attack technique consists of an attacker sending a DNS name lookup
  request to an open recursive DNS server with the source address spoofed to be
  the victim's address. When the DNS server sends the DNS record response, it is
  sent instead to the victim. Attackers will typically submit a request for as
  much zone information as possible to maximize the amplification effect. Because
  the size of the response is typically considerably larger than the request, the
  attacker is able to amplify the volume of traffic directed at the victim. By
  leveraging a botnet to perform additional spoofed DNS queries, an attacker can
  produce an overwhelming amount of traffic with little effort. Additionally,
  because the responses are legitimate data coming from valid servers, it is
  especially difficult to block these types of attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"A misconfigured Domain Name System (DNS)server can be exploited to participate
  in a Distributed Denial of Service (DDoS) attack.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("network_func.inc");

if( islocalnet() || islocalhost() || is_private_addr() ) exit( 0 );

port = get_kb_item( "Services/udp/domain" );
if ( ! port ) port = 53;

if( ! get_udp_port_state( port ) ) exit( 0 );

soc = open_sock_udp( port );
if( ! soc ) exit( 0 );

data = raw_string( 0x80, 0xa5, 0x00, 0x10, 0x00, 0x01,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x02, 0x00, 0x01 );
req_len = strlen( data );

send( socket:soc, data:data );
buf = recv( socket:soc, length:4096 );
resp_len = strlen( buf );

close( soc );

if( resp_len > ( 2 * req_len ) ) {

  data = 'We send a DNS request of ' + req_len + ' bytes and received a response of ' + resp_len + ' bytes.\n';
  security_message( port:port, data:data, proto:"udp" );
  exit( 0 );
}

exit( 99 );
