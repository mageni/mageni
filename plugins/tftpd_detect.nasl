###############################################################################
# OpenVAS Vulnerability Test
# $Id: tftpd_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# TFTP detection
#
# Authors:
# Vlatko Kosturjak
#
# Copyright:
# Copyright (C) 2009 Vlatko Kosturjak
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
  script_oid("1.3.6.1.4.1.25623.1.0.80100");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-04 10:25:48 +0100 (Wed, 04 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_copyright("Copyright (C) 2009 Vlatko Kosturjak");
  script_name("TFTP detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_require_udp_ports(69);

  script_tag(name:"solution", value:"Disable TFTP server if not used.");

  script_tag(name:"summary", value:"The remote host has a TFTP server running. TFTP stands
  for Trivial File Transfer Protocol.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("global_settings.inc");
include("dump.inc");
include("tftp.inc");

foundtftp = FALSE;

# taken from tftpd_dir_trav.nasl, adapted a bit
function tftp_grab( port, file, mode ) {

  local_var req, rep, sport, ip, u, filter, data, i;

  req = '\x00\x01' + file + '\0' + mode + '\0';

  sport = rand() % 64512 + 1024;

  if( TARGET_IS_IPV6() ) {

    IP6_v = 0x60;
    IP6_P = IPPROTO_UDP;
    IP6_HLIM = 0x40;
    ip6_packet = forge_ipv6_packet( ip6_v:IP6_v,
                                    ip6_p:IP6_P,
                                    ip6_plen:20,
                                    ip6_hlim:IP6_HLIM,
                                    ip6_src:this_host(),
                                    ip6_dst:get_host_ip() );

    udppacket = forge_udp_v6_packet( ip6:ip6_packet,
                                     uh_sport:sport,
                                     uh_dport:port,
                                     uh_ulen:8 + strlen( req ),
                                     data:req );

    filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and dst host ' + this_host();

    for( i = 0; i < 2; i++ ) { # Try twice

      rpkt = send_v6packet( udppacket, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1 );
      if( ! rpkt ) continue;

      data = get_udp_v6_element( udp:rpkt, element:"data" );
      if( isnull( data ) || strlen( data ) < 2 ) continue;

      if( data[0] == '\0' ) {
        if( data[1] == '\x03' || data[1] =='\x05' ) {
          foundtftp = TRUE;
          break;
        }
      }
    }
  } else {

    ip = forge_ip_packet( ip_hl:5,
                          ip_v:4,
                          ip_tos:0,
                          ip_len:20,
                          ip_off:0,
                          ip_ttl:64,
                          ip_p:IPPROTO_UDP,
                          ip_src:this_host() );

    u = forge_udp_packet( ip:ip,
                          uh_sport:sport,
                          uh_dport:port,
                          uh_ulen:8 + strlen( req ),
                          data:req );

    filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and udp[8:1]=0x00';

    data = NULL;
    for( i = 0; i < 2; i ++ ) { # Try twice

      rep = send_packet( u, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1 );
      if( ! rep ) continue;
      if( debug_level > 2 ) dump( ddata:rep, dtitle:'TFTP (IP)' );

      data = get_udp_element( udp:rep, element:"data" );
      if( debug_level > 1 ) dump( ddata:data, dtitle:'TFTP (UDP)' );
      if( isnull( data ) || strlen( data ) < 2 ) continue;

      if( data[0] == '\0' ) {
        if( data[1] == '\x03' || data[1] =='\x05' ) {
          foundtftp = TRUE;
          break;
        }
      }
    }

    # safeguard against some random/broken responses
    if( foundtftp ) {
      if( tftp_get( port:port, path:rand_str( length:10 ) ) )
        set_kb_item( name:"tftp/" + port + "/rand_file_response", value:TRUE );
    }
  }
}

port = 69;
if( ! get_udp_port_state( port ) ) exit( 0 );

rndfile = "nonexistant-" + rand_str();

# test valid modes according to RFC-783
tftp_grab( port:port, file:rndfile, mode:"netascii" );

if( ! foundtftp ) {
  tftp_grab( port:port, file:rndfile, mode:"octet" );
}

if( ! foundtftp ) {
  tftp_grab( port:port, file:rndfile, mode:"mail" );
}

if( foundtftp ) {
  register_service( port:port, ipproto:"udp", proto:"tftp" );
  log_message( port:port, proto:"udp" );
  set_kb_item( name:"tftp/detected", value:TRUE );
}

exit( 0 );