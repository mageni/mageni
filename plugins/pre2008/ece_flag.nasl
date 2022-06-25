###############################################################################
# OpenVAS Vulnerability Test
#
# Firewall ECE-bit bypass
#
# Authors:
# Andrey I. Zakharov
# John Lampe
#
# Copyright:
# Copyright (C) 2004 Andrey I. Zakharov and John Lampe
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
  script_oid("1.3.6.1.4.1.25623.1.0.12118");
  script_version("2019-04-24T07:26:10+0000");
  script_cve_id("CVE-2001-0183");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2293);
  script_name("Firewall ECE-bit bypass");
  script_category(ACT_GATHER_INFO);
  script_family("Firewalls");
  script_copyright("This script is Copyright (C) 2004 Andrey I. Zakharov and John Lampe");
  script_dependencies("os_detection.nasl", "global_settings.nasl");
  script_mandatory_keys("Host/runs_unixoide");
  script_exclude_keys("keys/islocalhost", "keys/islocalnet", "keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2293/");

  script_tag(name:"summary", value:"The remote host seems vulnerable to a bug wherein a remote
  attacker can circumvent the firewall by setting the ECE bit within the TCP flags field.");

  script_tag(name:"affected", value:"At least one firewall (ipfw) is known to exhibit this sort
  of behavior.

  Known vulnerable systems include all FreeBSD 3.x, 4.x, 3.5-STABLE, and 4.2-STABLE.");

  script_tag(name:"solution", value:"If you are running FreeBSD 3.X, 4.x, 3.5-STABLE,
  4.2-STABLE, upgrade your firewall. If you are not running FreeBSD,
  contact your firewall vendor for a patch.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");

if( islocalnet() || islocalhost() || TARGET_IS_IPV6() )
  exit( 0 );

# nb: Doesn't make much sense these days to run this against any other system out there...
if( host_runs( "freebsd" ) != "yes" )
  exit( 0 );

sport = ( rand() % 64511 ) + 1024;
ipid  = 1234;
myack = 0xFF67;
init_seq = 538;

# so, we need a list of commonly open, yet firewalled ports...
foreach port( make_list( 22, 111, 1025, 139, 3389, 23 ) ) {

  reply = NULL;
  sport++;
  filter = string("src port ", port, " and src host ", get_host_ip(), " and dst port ", sport);

  # STEP 1: Send a Naked SYN packet
  ip = forge_ip_packet( ip_v:4, ip_hl:5, ip_tos:0, ip_off:0, ip_len:20,
                        ip_p:IPPROTO_TCP, ip_id:ipid, ip_ttl:0x40,
                        ip_src:this_host() );

  tcp = forge_tcp_packet( ip:ip, th_sport:sport, th_dport:port,
                          th_flags:0x02, th_seq:init_seq, th_ack:myack,
                          th_x2:0, th_off:5, th_win:2048, th_urp:0 );

  for( i = 0 ; i < 3; i++ ) {
    reply = send_packet( tcp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1 );
    if( reply ) break;
  }

  # STEP 2: If we don't get a response back from STEP 1, we will send a SYN+ECE to port
  if( ! reply ) {
    sport++;
    filter = string( "src port ", port, " and src host ", get_host_ip(), " and dst port ", sport );
    ip = forge_ip_packet( ip_v:4, ip_hl:5, ip_tos:0, ip_off:0, ip_len:20,
                          ip_p:IPPROTO_TCP, ip_id:ipid, ip_ttl:0x40,
                          ip_src:this_host() );

    tcp = forge_tcp_packet( ip:ip, th_sport:sport, th_dport:port,
                            th_flags:0x42, th_seq:init_seq, th_ack:myack,
                            th_x2:0, th_off:5, th_win:2048, th_urp:0 );

    for( i = 0; i < 3; i++ ) {
      reply = send_packet( pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1, tcp );
      if( reply ) break;
    }

    if( reply ) {
      flags = get_tcp_element( tcp:reply, element:"th_flags" );
      if( flags & TH_ACK ) security_message( port:port );
    }
  }
}

exit( 0 );