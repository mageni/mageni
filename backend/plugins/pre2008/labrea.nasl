###############################################################################
# OpenVAS Vulnerability Test
# $Id: labrea.nasl 10411 2018-07-05 10:15:10Z cfischer $
#
# scan for LaBrea tarpitted hosts
#
# Authors:
# John Lampe...j_lampe@bellsouth.net
#
# Copyright:
# Copyright (C) 2001 by John Lampe
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
  script_oid("1.3.6.1.4.1.25623.1.0.10796");
  script_version("$Revision: 10411 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-05 12:15:10 +0200 (Thu, 05 Jul 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("scan for LaBrea tarpitted hosts");
  script_category(ACT_SCANNER);
  script_copyright("This script is Copyright (C) 2001 by John Lampe");
  script_family("Port scanners");
  script_dependencies("ping_host.nasl");
  script_exclude_keys("keys/TARGET_IS_IPV6"); # nb: This doesn't work as global_settings.nasl is in ACT_SETTINGS which is > ACT_SCANNER so we can't run global_settings.nasl before this one...

  script_tag(name:"summary", value:"This script performs a labrea tarpit scan, by
  sending a bogus ACK and ACK-windowprobe to a potential host. It also sends a TCP SYN
  to test for non-persisting labrea machines.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}


if(TARGET_IS_IPV6())exit(0);
include('global_settings.inc');

# Labrea only answers to TCP probes
if (get_kb_item('/tmp/ping/ICMP') )
{
 debug_print('Host answered to ICMP or UDP probes - cannot be "tar pitted"\n');
 exit(0);
}

src = this_host();
dst = get_host_ip();
sport=3133;
dport=rand() % 65535;
init_seq=2357;
init_ip_id = 1234;
filter = string("src port ", dport, " and src host ", dst);
myack = 0xFF67;
init_seq = 538;
init_ip_id = 12;
winsize = 100;
flags = 0;

debug_print(level: 2, 'sport=',sport, ' - dport=',dport,'\n');

# send two ACKs with a single byte as data (probe window)
# Labrea in persist mode will ACK the packet below after the initial
# "ARP-who has" timeout (defaults to 3 seconds, hence the 2 packets)

for (q=0; q<2; q = q + 1) {
    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0,ip_off:0,ip_len:20,
                         ip_p:IPPROTO_TCP, ip_id:init_ip_id, ip_ttl:0x40,
                         ip_src:this_host());

    tcp = forge_tcp_packet(ip:ip, th_sport:sport, th_dport:dport,
                          th_flags:TH_ACK, th_seq:init_seq,th_ack:myack,
                          th_x2:0, th_off:5, th_win:2048, th_urp:0, data:"H");



    reply =  send_packet(pcap_active : TRUE,
                        pcap_filter : filter,
                        pcap_timeout : 3,
                        tcp);
}


if(!reply)exit(0);



winsize = get_tcp_element(tcp:reply, element:"th_win");
flags = get_tcp_element(tcp:reply, element:"th_flags");

# don't know when this would be true...but adding it nonetheless
if (flags & TH_RST) {
    exit(0);
}



if ( (winsize <= 10) && (flags & TH_ACK) ) {
      set_kb_item( name:"Host/dead", value:TRUE );
      exit(0);
}




# now handle LaBrea in non-persist mode

    winsize = 100;
    flags = 0;

    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0,ip_off:0,ip_len:20,
                         ip_p:IPPROTO_TCP, ip_id:init_ip_id, ip_ttl:0x40,
                         ip_src:this_host());

    tcp = forge_tcp_packet(ip:ip, th_sport:sport, th_dport:dport,
                          th_flags:TH_SYN, th_seq:init_seq,th_ack:0,
                          th_x2:0, th_off:5, th_win:2048, th_urp:0);



    reply2 =  send_packet(pcap_active : TRUE,
                        pcap_filter : filter,
                        pcap_timeout : 5,
                        tcp);


    winsize = get_tcp_element(tcp:reply2, element:"th_win");
    flags = get_tcp_element(tcp:reply2, element:"th_flags");
    if ( (flags & TH_ACK) && (flags & TH_SYN) && (winsize == 10) ) {
        set_kb_item( name:"Host/dead", value:TRUE );
        exit(0);
    }

exit(0);



