###############################################################################
# OpenVAS Vulnerability Test
# $Id: tcp_timestamps.nasl 14310 2019-03-19 10:27:27Z cfischer $
#
# TCP timestamps
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2007 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80091");
  script_version("$Revision: 14310 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:27:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_name("TCP timestamps");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2007 Michel Arboi");
  script_dependencies("secpod_open_tcp_ports.nasl", "global_settings.nasl");
  script_mandatory_keys("TCP/PORTS");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");

  script_add_preference(name:"Delay (seconds):", value:"1", type:"entry");

  script_xref(name:"URL", value:"http://www.ietf.org/rfc/rfc1323.txt");
  script_xref(name:"URL", value:"http://www.microsoft.com/en-us/download/details.aspx?id=9152");

  script_tag(name:"summary", value:"The remote host implements TCP timestamps and therefore allows to compute
  the uptime.");

  script_tag(name:"vuldetect", value:"Special IP packets are forged and sent with a little delay in between to the
  target IP. The responses are searched for a timestamps. If found, the timestamps are reported.");

  script_tag(name:"solution", value:"To disable TCP timestamps on linux add the line 'net.ipv4.tcp_timestamps = 0' to
  /etc/sysctl.conf. Execute 'sysctl -p' to apply the settings at runtime.

  To disable TCP timestamps on Windows execute 'netsh int tcp set global timestamps=disabled'

  Starting with Windows Server 2008 and Vista, the timestamp can not be completely disabled.

  The default behavior of the TCP/IP stack on this Systems is to not use the
  Timestamp options when initiating TCP connections, but use them if the TCP peer
  that is initiating communication includes them in their synchronize (SYN) segment.

  See the references for more information.");

  script_tag(name:"affected", value:"TCP/IPv4 implementations that implement RFC1323.");

  script_tag(name:"insight", value:"The remote host implements TCP timestamps, as defined by RFC1323.");

  script_tag(name:"impact", value:"A side effect of this feature is that the uptime of the remote
  host can sometimes be computed.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("network_func.inc");
include("misc_func.inc");
include("dump.inc");

if( TARGET_IS_IPV6() ) exit( 0 );
if( islocalhost() ) exit( 0 );

debug = FALSE;

function test( seq, saddr, daddr, dport ) {

  local_var ip, tcp, options, filter, ms, r, sport, seq, tsval;

  sport = rand() % ( 65536 - 1024 ) + 1024;
  ip = forge_ip_packet( ip_v:4, ip_hl:5, ip_tos:0,
                        ip_len:20, ip_id:rand(), ip_p:IPPROTO_TCP,
                        ip_ttl:255, ip_off:0, ip_src:saddr );

  options = strcat( '\x08',         # Timestamp option
                    '\x0A',         # length
                    htonl( n:seq ), # TSVal
                    '\0\0\0\0',     # TSecr is invalid as ACK is not set
                    '\x01\x01' );   # NOP padding

  tcp = forge_tcp_packet( ip:ip, th_sport:sport, th_dport:dport,
                          th_flags:TH_SYN, th_seq:rand(),
                          th_ack:0, th_x2:0, th_off:8,
                          th_win:512, th_urp:0, data:options );

  filter = strcat( 'tcp and src ', daddr, ' and dst ', saddr, ' and src port ', dport, ' and dst port ', sport );
  r = send_packet( tcp, pcap_active:TRUE, pcap_filter:filter );
  ms = ms_since_midnight();

  tsval = tcp_extract_timestamp( ip:r );
  if( isnull( tsval ) ) return NULL;
  return make_list( ms, tsval );
}

function tcp_extract_timestamp( ip ) {

  local_var hl, hlen, tcp, flags, opt, lo, i, n, tsval, tsecr, len, ip;

  if( isnull( ip ) || strlen( ip ) < 20 ) return NULL;

  hl = ord( ip[0] );
  hlen = ( hl & 0xF ) * 4;
  tcp = substr( ip, hlen );

  if( debug ) {
    dump( ddata:ip, dtitle:'IP' );
    dump( ddata:tcp, dtitle:'TCP' );
  }

  if( strlen( tcp ) <= 20 ) return NULL;
  flags = ord( tcp[13] );
  if( ! ( flags & TH_ACK ) ) return NULL;

  opt = substr( tcp, 20 );
  if( debug ) dump( ddata:opt, dtitle:'TCP options' );

  lo = strlen( opt );

  for( i = 0; i < lo; ) {
    n = ord( opt[i] );

    if( n == 8 ) { # Timestamp
      tsval = ntohl( n:substr( opt, i+2, i+5 ) );
      if( int( tsval ) == NULL ) return NULL;
      tsecr = ntohl( n:substr( opt, i+6, i+9 ) );
      if( debug ) display("TSVal=", tsval, " TSecr=", tsecr, "\n" );
      return tsval;
    } else if( n == 1 ) { # NOP
      i ++;
    } else {
      len = ord( opt[i+1] );
      if( len == 0 ) break;
      i += len;
    }
  }
  return NULL;
}

dport = get_host_open_tcp_port();

daddr = get_host_ip();
saddr = this_host();

v1 = test( seq:1, daddr:daddr, saddr:saddr, dport:dport );

if( isnull( v1 ) ) exit( 0 );

# A linear regression would not be more precise and NASL is definitely not
# designed for computation! We would need floating point.
delay = script_get_preference( "Delay (seconds):" );
if( ! delay || int( delay ) < 1 ) {
  delay = 1;
}

sleep( delay );

v2 = test( seq:2, daddr:daddr, saddr:saddr, dport:dport );
if( isnull( v2 ) ) exit( 1 ); # ???

dms = v2[0] - v1[0];
dseq = v2[1] - v1[1];

result = 'It was detected that the host implements RFC1323.';

# TODO: Remove once we are able to handle received timestamps larger then a 32bit integer
if( v2[1] > 0 ) {
  result += '\n\nThe following timestamps were retrieved with a delay of ' +
            delay + ' seconds in-between:\n' +
            'Packet 1: ' + v1[1] + '\n' +
            'Packet 2: ' + v2[1];
}

security_message( data:result );

exit( 0 );
