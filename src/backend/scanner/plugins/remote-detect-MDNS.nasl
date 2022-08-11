###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-detect-MDNS.nasl 12413 2018-11-19 11:11:31Z cfischer $
#
# MDNS Service Detection
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# Fixed by Michael Meyer <michael.meyer@greenbone.net> 09.03.11
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2+,
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
  script_oid("1.3.6.1.4.1.25623.1.0.101013");
  script_version("$Revision: 12413 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-03-16 00:46:49 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("MDNS Service Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Written by Christian Eric Edjenguele <christian.edjenguele@owasp.org>  and released under GPL v2 or later");
  script_family("Service detection");
  script_require_udp_ports("Services/udp/mdns", 5353);

  script_tag(name:"solution", value:"It's recommended to disable this service if not used.");

  script_tag(name:"summary", value:"The Remote Host is Running the MDNS Service.
  Zeroconf, or Zero Configuration Networking, often known as MDNS or Bonjour/rendez-vous,
  is a set of techniques that automatically create a usable IP network without configuration or special servers.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("dump.inc");

function grabHostInfos( stringa ) {

  local_var stringa, length, stradds, pad, addr, na, nb, n, hostname, infos;

  if( strlen( stringa ) < 51 ) return;

  length = ord( stringa[51] ) * 256 + ord( stringa[52] ) - 1;

  straddr = substr( stringa , 54, 51 + length );
  pad = split( straddr, sep:"[" );

  addr = str_replace( string:pad[1], find:"]", replace:"" );
  na = str_replace( string:pad[0], find:raw_string( 0xe2, 0x80, 0x99 ), replace:"" );
  nb = str_replace( string:na, find:"\ ", replace:"-" );
  n  = str_replace( string:nb, find:"\'", replace:"" );
  hostname = eregmatch( pattern:"([^ ]+)", string:n );

  # save the mac address and hostname
  infos = make_array( 0, addr, 1, hostname[0] );
  return( infos );
}

function grabCpuInfos( stringa ) {

  local_var stringa, offset, cpu_len, mn, mj, cpu_type, minor, major, pados, os, os_x, infos;

  if( strlen( stringa ) < 11 ) return;

  offset = 13 + ord( stringa[12] ) + 23;

  # determine the limits to extract cpu type
  cpu_len = ord( stringa[offset] );
  mn = offset + 1;
  mj = mn + cpu_len;
  cpu_type = substr( stringa , mn , mj );

  # determine the limits to extract operating system type
  offset += cpu_len + 1;
  minor = offset + 1;
  major = minor + ord( stringa[offset] );

  pados = substr( stringa , minor , major );
  os = split( pados, sep:";" );
  os_x = os[0];

  # save cpu type and operating system
  infos = make_array( 0, cpu_type, 1, os_x );

  return( infos );
}

function createMDNSQuery( query, itype ) {

  local_var query, itype, pkt1, pkt2, length, element;

  pkt2 = "";
  pkt1 = raw_string( 0x00, 0x4a, 0x01, 0x00, 0x00, 0x01,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

  foreach element( query ) {
    length = strlen( element );
    pkt1 += raw_string( length ) + element;
  }

  if( itype == 'PTR' )
    pkt1 += raw_string( 0x00, 0x00, 0x0c, 0x00, 0x01 );

  if( itype == 'HINFO' ) {
    foreach element( query ) {
      pkt1 = pkt1 + raw_string( 0x00, 0x0d, 0x00, 0x01, 0x00 );
      return( pkt1 );
    }
  }
  return( pkt1 );
}

port = get_kb_item( "Services/udp/mdns") ;
if( ! port ) port = 5353;
if( ! get_udp_port_state( port ) ) exit( 0 );

soc = open_sock_udp( port );
if( ! soc ) exit( 0 );

qry1 = make_list( '_daap', '_tcp', 'local' );
qry2 = make_list( '_workstation', '_tcp', 'local' );

# forge the MDNS Host Infos negotiation protocol
pkt1 = createMDNSQuery( query:qry1, itype:'PTR' );
pkt2 = createMDNSQuery( query:qry2, itype:'PTR' );

send( socket:soc, data:pkt1 );
send( socket:soc, data:pkt2 );

reply = recv( socket:soc, length:1024 );

if( reply ) {

  hostinfos = grabHostInfos( stringa:reply );

  if( typeof( hostinfos ) == "array" ) {
    qry3 = make_list( hostinfos[1], 'local', '' );

    # forge the MDNS CPU Infos negotiation protocol
    pkt3 = createMDNSQuery( query:qry3, itype:'HINFO' );

    send( socket:soc, data:pkt3 );
    reply = recv( socket:soc, length:1 );
    reply = recv( socket:soc, length:1024 );

    cpuinfos = grabCpuInfos( stringa:reply );
  }

  register_service( port:port, ipproto:"udp", proto:"mdns" );
}

close( soc );

report = '';

# save gathered information into variables
if( strlen( hostinfos[1] ) > 1 ) {
  hostname = hostinfos[1];
  report  += 'Hostname: ' + hostname;
  set_kb_item( name:"MDNS/Host/hostname", value:hostname );
}

if( strlen( hostinfos[0] ) > 1 ) {
  mac_address = hostinfos[0];
  report += ' \nMAC Address: ' + mac_address;
  set_kb_item( name:"MDNS/Host/MacAddress", value:mac_address );
  register_host_detail( name:"MAC", value:mac_address, desc:"MDNS Service Detection" );
}

if( strlen( cpuinfos[0] ) > 1 ) {
  cpu_type = cpuinfos[0];
  report += '\nCPU Type: ' + cpu_type;
  set_kb_item( name:"MDNS/Host/CpuType", value:cpu_type );
}

if( strlen( cpuinfos[1] ) >1 ) {
  operating_system = cpuinfos[1];
  report += '\nOperating System: ' + operating_system;
  set_kb_item( name:"MDNS/Host/OS", value:operating_system );

  if( "linux" >< tolower( operating_system ) ) {
    register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner:operating_system, banner_type:"MDNS banner", port:port, proto:"udp", desc:"MDNS Service Detection", runs_key:"unixoide" );
  } else if( "windows" >< tolower( operating_system ) ) {
    register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner:operating_system, banner_type:"MDNS banner", port:port, proto:"udp", desc:"MDNS Service Detection", runs_key:"windows" );
  } else if( "mac os x" >< tolower( operating_system ) ) {
    register_and_report_os( os:"Mac OS X", cpe:"cpe:/o:apple:mac_os_x", banner:operating_system, banner_type:"MDNS banner", port:port, proto:"udp", desc:"MDNS Service Detection", runs_key:"unixoide" );
  } else {
    register_unknown_os_banner( banner:operating_system, banner_type_name:"MDNS banner", banner_type_short:"mdns_banner", port:port, proto:"udp" );
  }
}

# report MDNS service running
if( strlen( report ) ) {
  log_message( port:port, data:report, protocol:"udp" );
}

exit( 0 );
