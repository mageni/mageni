# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117692");
  script_version("2021-09-24T13:56:13+0000");
  script_tag(name:"last_modification", value:"2021-09-27 10:21:48 +0000 (Mon, 27 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-24 13:00:19 +0000 (Fri, 24 Sep 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Network Time Protocol (NTP) Mode 6 Query Response Check");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("ntp_open.nasl", "global_settings.nasl");
  script_mandatory_keys("ntp/mode6/response/received", "keys/is_public_addr");

  script_xref(name:"URL", value:"https://scan.shadowserver.org/ntpversion/");

  script_tag(name:"summary", value:"Checks if the remote Network Time Protocol (NTP) service has
  responded to Mode 6 Queries.");

  script_tag(name:"insight", value:"If a service supporting NTP is publicly accessible and is
  responding to Mode 6 Queries it can participate in an Amplification based Distributed Denial of
  Service (DDoS) attack.

  An Amplification attack is a popular form of Distributed Denial of Service (DDoS) that relies on
  the use of publicly accessible NTP services to overwhelm a victim system with response traffic.

  The basic attack technique consists of an attacker sending a valid query request to a NTP service
  with the source address spoofed to be the victim's address. When the Memcached server sends the
  response, it is sent instead to the victim. Attackers will typically first inserting records into
  the open server to maximize the amplification effect. Because the size of the response is
  typically considerably larger than the request, the attacker is able to amplify the volume of
  traffic directed at the victim. By leveraging a botnet to perform additional spoofed queries, an
  attacker can produce an overwhelming amount of traffic with little effort. Additionally, because
  the responses are legitimate data coming from valid clients, it is especially difficult to block
  these types of attacks.");

  script_tag(name:"solution", value:"The following mitigation possibilities are currently available:

  - Generally disable public access to the UDP port of this NTP service.

  - Only allow Mode 6 queries by trusted clients / networks.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("network_func.inc");
include("port_service_func.inc");

if( ! is_public_addr() )
  exit( 99 );

port = service_get_port( default:123, ipproto:"udp", proto:"ntp" );

if( ! get_kb_item( "ntp/mode6/response/" + port + "/received" ) )
  exit( 99 );

if( ! recv_data_len = get_kb_item( "ntp/mode6/response/" + port + "/recv_data_len" ) )
  exit( 99 );

if( ! sent_data_len = get_kb_item( "ntp/mode6/response/" + port + "/sent_data_len" ) )
  exit( 99 );

if( recv_data_len > ( 20 * sent_data_len ) ) {
  report = 'The remote NTP service responded on Mode 6 queries. We have sent a query request of ' + sent_data_len + ' bytes and received a response of ' + recv_data_len + ' bytes.';
  security_message( port:port, data:report, proto:"udp" );
  exit( 0 );
}

exit( 99 );