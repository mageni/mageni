###############################################################################
# OpenVAS Vulnerability Test
# $Id: ms_rdp_detect.nasl 11031 2018-08-17 09:42:45Z cfischer $
#
# Microsoft Remote Desktop Protocol Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100062");
  script_version("$Revision: 11031 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 11:42:45 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-03-19 19:54:28 +0100 (Thu, 19 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Microsoft Remote Desktop Protocol Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "find_service1.nasl");
  script_require_ports("Services/unknown", "Services/ms-wbt-server", 3389);

  script_tag(name:"summary", value:"A service supporting the Microsoft Remote Desktop Protocol (RDP) is running
  at this host.

  Remote Desktop Services, formerly known as Terminal Services, is one of the components of Microsoft Windows
  (both server and client versions) that allows a user to access applications and data on a remote computer over
  a network.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("http_func.inc"); # For make_list_unique

SCRIPT_DESC = "Microsoft Remote Desktop Protocol Detection";
BANNER_TYPE = "Microsoft Remote Desktop Protocol";

function check_xrdp( port ) {

  local_var port, soc, req, buf, hexbuf;

  if( get_kb_item( "rdp/" + port + "/isxrdp" ) ) return TRUE;

  # Enforce plaintext, if we're using SSL/TLS the detection below
  # seems to fail and we only want to catch the first response anyway...
  soc = open_sock_tcp( port, transport:ENCAPS_IP );
  if( ! soc ) return FALSE;

  req = 'GET / HTTP/1.0\r\n\r\n';
  send( socket:soc, data:req );
  buf = recv( socket:soc, length:9 );
  close( soc );
  if( isnull( buf ) || strlen( buf ) != 9 ) return FALSE;

  hexbuf = hexstr( buf );

  # Some older Xrdp versions are responding with the string below
  # if a GET request is sent (see find_service1.nasl)
  if( hexbuf == "0300000902f0802180" )
    return TRUE;

  return FALSE;
}

function check_without_cookie( port ) {

  local_var port, soc, req, buf, hexbuf;

  # Enforce plaintext, if we're using SSL/TLS the detection below
  # seems to fail and we only want to catch the first response anyway...
  soc = open_sock_tcp( port, transport:ENCAPS_IP );
  if( ! soc ) return FALSE;

  # found in amap (https://github.com/BlackArch/amap/blob/master/appdefs.trig#L60)
  req = raw_string( 0x03, 0x00, 0x00, 0x0b, 0x06,
                    0xe0, 0x00, 0x00, 0x00, 0x00, 0x00 );

  send( socket:soc, data:req );
  buf = recv( socket:soc, length:11 );
  close( soc );
  if( isnull( buf ) || strlen( buf ) != 11 ) return FALSE;

  hexbuf = hexstr( buf );

  # All tested windows systems and Xrdp on Debian 9 returned the first string
  # where Xrdp on Debian 8 the latter. For the second case there is check_xrdp above.
  if( hexbuf =~ "^0300000b06d00000123400$" || hexbuf =~ "^0300000b06d00000000000$" )
    return TRUE;

  return FALSE;
}

function check_with_cookie( port ) {

  local_var port, soc, req, buf, hexbuf;

  # Enforce plaintext, if we're using SSL/TLS the detection below
  # seems to fail and we only want to catch the first response anyway...
  soc = open_sock_tcp( port, transport:ENCAPS_IP );
  if( ! soc ) return FALSE;

  # From a wireshark dump when connecting via remmina
  # to a remote RDP service running on Windows 10.
  # Also see http://www.jasonfilley.com/rdpcookies.html
  # nb: This is required if the Windows System has "Allow Connections Only From Computers Running
  # Remote Desktop With Network Level Authentication (More Secure)." enabled.
  req  = raw_string( 0x03, 0x00, 0x00 );
  req += "-("; # nb: This seems to be changed / variable depending on the cookie name below...
  req += raw_string( 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00 );
  req += 'Cookie: mstshash=openvas\r\n';
  req += raw_string( 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 );

  send( socket:soc, data:req );
  buf = recv( socket:soc, length:19 );
  close( soc );
  if( isnull( buf ) || ( strlen( buf ) != 11 && strlen( buf ) != 19 ) ) return FALSE;

  hexbuf = hexstr( buf );

  # Those are basic fingerprints which might even change based on the RDP configuration.
  # TODO: We should evaluate more fingerprints for a reliable Detection
  if( hexbuf =~ "^030000130ed000001234000200080002000000$" )
    return make_list( "Windows, possible Windows Vista or Server 2008", hexbuf );

  if( hexbuf =~ "^030000130ed000001234000209080002000000$" || hexbuf =~ "^030000130ed000001234000201080002000000$" )
    return make_list( "Windows, possible Windows 7 or Server 2008", hexbuf );

  if( hexbuf =~ "^030000130ed00000123400021f080002000000$" )
    return make_list( "Windows, possible Windows 10 or Server 2016", hexbuf );

  if( hexbuf =~ "^030000130ed00000123400020f080002000000$" )
    return make_list( "Windows, possible Windows 8, 8.1 or Server 2012", hexbuf );

  if( hexbuf =~ "^030000130ed000001234000300080002000000$" )
    return make_list( "Windows, possible Windows XP 64bit SP2 or Server 2003", hexbuf );

  if( hexbuf =~ "^030000130ed000001234000207080002000000$" )
    return make_list( "Windows, possible Windows 8 build 9200", hexbuf );

  # Some Windows variants (e.g. Windows XP) returned this shorter string
  if( hexbuf =~ "^0300000b06d00000123400$" )
    return make_list( "Windows, possible Windows XP SP2/SP3", hexbuf );

  # Xrdp on Debian 8
  if( hexbuf =~ "^0300000b06d00000000000$" )
    return make_list( "Unixoide", hexbuf );

  # Xrdp on Debian 9
  if( hexbuf =~ "^030000130ed000001234000201080000000000$" )
    return make_list( "Unixoide", hexbuf );

  # Unknown implementation
  if( hexbuf =~ "^030000130ed000001234000....80002000000$" )
    return make_list( "Unknown", hexbuf );

  return FALSE;
}

# The default port. TBD: Add others like 3388?
ports = make_list( 3389 );

unknown_ports = get_unknown_port_list( default:3389 );
if( ! isnull( unknown_ports ) )
  ports = make_list( ports, unknown_ports );

known_ports = get_kb_list( "Services/ms-wbt-server" ); # If Xrdp was detected in find_service1.nasl...
if( ! isnull( known_ports ) )
  ports = make_list( ports, known_ports );

ports = make_list_unique( ports );

foreach port( ports ) {

  if( ! get_port_state( port ) ) continue;
  found  = FALSE;
  isxrdp = FALSE;

  if( fp = check_with_cookie( port:port ) ) {
    found = TRUE;
  }

  if( ! found ) {
    if( check_without_cookie( port:port ) ) {
      found = TRUE;
      if( check_xrdp( port:port ) )
        isxrdp = TRUE;
    }
  }

  if( found ) {
    if( fp ) {
      report = fp[0] + " based on binary response fingerprinting: " + fp[1];
      if( "Windows" >< fp[0] ) {
        register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner:report, banner_type:BANNER_TYPE, port:port, desc:SCRIPT_DESC, runs_key:"windows" );
        set_kb_item( name:"msrdp/detected", value:TRUE );
        set_kb_item( name:"rdp/detected", value:TRUE );
      } else if( "Unixoide" >< fp[0] ) {
        register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner:report, banner_type:BANNER_TYPE, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
        set_kb_item( name:"rdp/detected", value:TRUE );
      } else {
        register_unknown_os_banner( banner:report, banner_type_name:BANNER_TYPE, banner_type_short:"rdp_binary_response", port:port );
        set_kb_item( name:"msrdp/detected", value:TRUE );
        set_kb_item( name:"rdp/detected", value:TRUE );
      }
    } else {
      if( isxrdp ) {
        register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner:"Connection reset message of Xrdp", banner_type:BANNER_TYPE, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
        set_kb_item( name:"rdp/detected", value:TRUE );
      } else {
        set_kb_item( name:"msrdp/detected", value:TRUE );
        set_kb_item( name:"rdp/detected", value:TRUE );
      }
    }
    register_service( port:port, proto:"ms-wbt-server" );
    log_message( port:port );
  }
}

exit( 0 );
