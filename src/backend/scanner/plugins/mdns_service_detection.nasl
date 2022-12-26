###############################################################################
# OpenVAS Vulnerability Test
#
# mDNS Service Detection
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
  script_version("2022-12-21T14:21:45+0000");
  script_tag(name:"last_modification", value:"2022-12-21 14:21:45 +0000 (Wed, 21 Dec 2022)");
  script_tag(name:"creation_date", value:"2009-03-16 00:46:49 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("mDNS Service Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Service detection");
  script_require_udp_ports("Services/udp/mdns", 5353);

  script_tag(name:"summary", value:"Detection of services supporting the Multicast DNS (mDNS)
  protocol.");

  script_tag(name:"insight", value:"Zeroconf, or Zero Configuration Networking, often known as mDNS
  or Bonjour/rendez-vous, is a set of techniques that automatically create a usable IP network
  without configuration or special servers.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");
include("byte_func.inc");
include("dns_func.inc");
include("network_func.inc");

transactionId = 0x4a;

ptrs = make_list();

# @brief Parses PTR answer to try to get the Host Name and when possible, the MAC Address.
#
# @param stringa the PTR answer to be parsed
#
# @return An array containing the host name and when the case, the MAC address
#
# @note In some cases, and only for _workstation._tcp.local queries,
#       mDNS contains a PTR Answer on the form <domain name> [<MAC Address>]
#
function grabHostInfos( stringa ) {

  local_var stringa;
  local_var length, stradds, pad, addr, na, nb, n, hostname, infos;

  length = ord( stringa[0] );

  straddr = substr( stringa , 1, length );

  if ( "[" >< straddr ) {
    pad = split( straddr, sep:"[", keep:FALSE );
    addr = str_replace( string:pad[1], find:"]", replace:"" );
    na = str_replace( string:pad[0], find:raw_string( 0xe2, 0x80, 0x99 ), replace:"" );
    nb = str_replace( string:na, find:"\ ", replace:"-" );
    n  = str_replace( string:nb, find:"\'", replace:"" );
    hostname = eregmatch( pattern:"([^ ]+)", string:n );

    # save the mac address and hostname
    infos = make_array( 0, hostname[0], 1, addr );
  } else {
    infos = make_array( 0, straddr );
  }

  return( infos );
}

# @brief Parses the reply to a HINFO query message and extract CPU type and OS
#
# @param stringa the HINFO reply to be parsed
#
# @return An array containing the CPU Type and OS
#
# @note It seems that this only works for queries messages for host_name.local,
#       where host_name is extracted from the PTR answer to a query to the _workstation._tcp.local domain name.
#       In these cases, mDNS may contain a PTR Answer on the form <domain name> [<MAC Address>]
#
function grabCpuInfos( stringa ) {

  local_var stringa;
  local_var offset, cpu_len, mn, mj, cpu_type, minor, major, pados, os, os_x, infos;

  if( strlen( stringa ) < 11 ) return;

  offset = 13 + ord( stringa[12] ) + 23;

  # determine the limits to extract cpu type
  cpu_len = ord( stringa[offset] );
  mn = offset + 1;
  mj = mn + cpu_len - 1;
  cpu_type = substr( stringa , mn , mj );

  # determine the limits to extract operating system type
  offset += cpu_len + 1;
  minor = offset + 1;
  major = minor + ord( stringa[offset] );

  pados = substr( stringa , minor , major );
  os = split( pados, sep:";", keep:FALSE );
  os_x = os[0];

  # save cpu type and operating system
  infos = make_array( 0, cpu_type, 1, os_x );

  return( infos );
}
# @brief Converts the list of labels to a proper QNAME
#
# @param labels the list of labels
#
# @return the binary QNAME
#
function listTomDNSQuery( labels ) {

  local_var labels;
  local_var query, element, length;

  query = "";
  foreach element( labels ) {
    length = strlen( element );
    query += raw_string( length ) + element;
  }

  query += raw_string( 0x00 ); # Root
  return query;
}

# @brief Creates a mDNS query message of the given itype type
#
# @param query The binary query
# @param itype The query type; for now PTR and HINFO are supported
#
# @return the mDNS query message
#
function createmDNSQuery( query, itype ) {

  local_var query, itype;
  local_var pkt2, pkt1;

  pkt2 = "";
  # DNS Header
  pkt1 = raw_string( 0x00, transactionId );
  pkt1 += raw_string( 0x01, 0x00,   # Flags: standard query
                      0x00, 0x01,   # Question count
                      0x00, 0x00,   # Answer count
                      0x00, 0x00,   # Authority RRS
                      0x00, 0x00 ); # Additional RRS
  pkt1 += query;

  if( itype == "PTR" )
    pkt1 += raw_string( 0x00, 0x0c, 0x00, 0x01 );

  if( itype == "HINFO" )
    pkt1 += raw_string( 0x00, 0x0d, 0x00, 0x01, 0x00 );

  return( pkt1 );
}

port = unknownservice_get_port( default:5353, ipproto:"udp" );

if( ! soc = open_sock_udp( port ) )
  exit( 0 );

# nb: this constructs a query to get the list of available services
list_services = make_list( "_services", "_dns-sd", "_udp", "local" );
query_services = listTomDNSQuery( labels:list_services );

pkt2 = createmDNSQuery( query:query_services, itype:"PTR" );

send( socket:soc, data:pkt2 );

reply = recv( socket:soc, length:1024 );
if( isnull( reply ) ) {
  close( soc );
  exit( 0 );
}

port_and_proto = port + "/udp";

set_kb_item( name:"mdns/port_and_proto", value:port_and_proto );

answers = parseDNSPTRResponse( r:reply, query:query_services );

ptrs = answers["PTR"];

if( max_index( ptrs ) > 0 ) {
  report = 'PTRS:\n';

  foreach _ptr( ptrs ) {
    domain_str = domainNameString( domainName:_ptr );
    report += '\t' + domain_str + '\n';
    set_kb_item( name:"mdns/" + port_and_proto + "/services/" + domain_str, value:TRUE );
  }

  host_name = "";
  # nb: Previous implementation was using a very hardcoded, limited case check to extract MAC address
  # This was extended to catch as many real-life cases as possible
  mac_address = "";
  services_report = "";

  foreach _ptr( ptrs ) {
    pkt2 = createmDNSQuery( query:_ptr, itype:"PTR" );

    send( socket:soc, data:pkt2 );

    reply = recv( socket:soc, length:1024 );
    if( isnull( reply ) )
      continue;

    services = parseDNSPTRResponse( r:reply, query:_ptr );
    # nb: making sure to reset the variables
    addresses = "";
    host_name = "";
    _port = 0;

    if( ! isnull( services["SRV"] ) ) {
      info = services["SRV"];
      _port = info["port"];
      host_name = info["name"];
    }

    if( ! isnull( services["PTR"] ) ) {
      _hst = services["PTR"];
      hostName = _hst[0];
      # nb: There should not be more than one PTR answer,
      # and anyway we always choose the first one for the hostName
      host_info = grabHostInfos( stringa:hostName );

      if( max_index( host_info ) > 1 && strlen( host_info[1] ) ) {
        mac_address = host_info[1];
      }
    }

    if( ! isnull( services["A"] ) ) {
      foreach ipv4( services["A"] )
        addresses += ipv4 + "  ";
    }
    if( ! isnull( services["AAA"] ) ) {
      foreach ipv6( services["AAA"] )
        addresses += ipv6 + "  ";
    }
    addresses = chomp( addresses );

    ptr_name = domainNameString( domainName:_ptr );

    serv_report = "";
    if( strlen( host_name ) ) {
      serv_report += '\t\tName=' + host_name + '\n';
      set_kb_item( name:"mdns/" + port_and_proto + "/services/" + ptr_name + "/info/name", value:host_name );
    }

    if( strlen( addresses ) )
      serv_report += '\t\tAddress=' + addresses + '\n';

    # nb: Sometimes, the first label obtained from the PTR response is different from the SRV name
    if( strlen( host_info[0] ) ) {
      serv_report += '\t\tHost Name=' + host_info[0] + '\n';
      set_kb_item( name:"mdns/" + port_and_proto + "/services/" + ptr_name + "/info/host_name", value:host_info[0] );
    }

    # nb: TXT data is returned unparsed
    foreach txt( services["TXT"] ) {

      length = strlen( txt );

      if( length && ord( txt[0] ) > 0 ) {
        offset = 0;
        while( offset < length && ord( txt[offset] ) > 0 ) {
          len = ord( txt[offset] );
          offset++;
          str = substr( txt, offset, offset + len - 1 );
          # nb: Sometimes TXT contains references to MAC Address
          if( "mac_address=" >< str || str =~ "MAC=" ) {
            pan = split( str, sep:"=" );
            mac_address = pan[1];
          }
          if( "=" >< str ) {
            parts = split( str, sep:"=", keep:FALSE );
            if( ! isnull( parts[1] ) ) {
              # nb: sometimes some services exposes a lot of info.
              set_kb_item( name:"mdns/" + port_and_proto + "/info/" + parts[0], value:parts[1] );
              set_kb_item( name:"mdns/" + port_and_proto + "/services/" + ptr_name + "/info/" + parts[0], value:parts[1] );
            }
          }
          offset += len;
          serv_report += '\t\t' + str + '\n';
        }
      }
    }

    if( ! isnull( _port ) && _port > 0 )
      set_kb_item( name:"mdns/" + port_and_proto + "/services/" + ptr_name + "/port", value:_port );

    if( strlen( serv_report ) ) {
      # nb: Only add details for a PTR if there is any info
      services_report += '\t';
      if( ! isnull( _port ) && _port > 0 )
        services_report += _port + "/";

      services_report += ptr_name + ':\n';
      services_report += serv_report + '\n';
    }
  }

  if( strlen( services_report ) ) {
    report += '\nServices:\n';
    report += services_report;
  }
}

if( strlen( host_name ) ) {
  list_hName = make_list( host_name, "local" );
  query_hName = listTomDNSQuery( labels:list_hName );

  # forge the mDNS CPU Infos negotiation protocol
  pkt3 = createmDNSQuery( query:query_hName, itype:"HINFO" );

  send( socket:soc, data:pkt3 );
  reply = recv( socket:soc, length:1 );
  reply = recv( socket:soc, length:1024 );

  cpuinfos = grabCpuInfos( stringa:reply );
}

service_register( port:port, ipproto:"udp", proto:"mdns" );

close( soc );

if( strlen( mac_address ) > 1 ) {

  # eg. 00:11:32:0d:04:b9|00:11:32:0d:04:ba
  if( "|" >< mac_address ) {
    macs = split( mac_address, sep:"|", keep:FALSE );
    mac_address = "";
    foreach mac( macs ) {
      v_mac = verify_register_mac_address( data:mac, desc:"mDNS Service Detection" );
      if( v_mac )
        mac_address += v_mac + "  ";
    }
    mac_address = chomp( mac_address );
  } else {
    mac_address = verify_register_mac_address( data:mac_address, desc:"mDNS Service Detection" );
  }

  if( ( ! isnull( mac_address ) ) && strlen( mac_address ) )
    report += ' \nMAC Address: ' + mac_address;
}

if( strlen( cpuinfos[0] ) > 1 ) {
  cpu_type = cpuinfos[0];
  report += '\nCPU Type: ' + cpu_type;
  set_kb_item( name:"MDNS/Host/CpuType", value:cpu_type );
}

if( strlen( cpuinfos[1] ) > 1 ) {
  operating_system = cpuinfos[1];
  report += '\nOperating System: ' + operating_system;
  set_kb_item( name:"MDNS/Host/OS", value:operating_system );

  if( "linux" >< tolower( operating_system ) ) {
    os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner:operating_system, banner_type:"mDNS banner", port:port, proto:"udp", desc:"mDNS Service Detection", runs_key:"unixoide" );
  } else if( "windows" >< tolower( operating_system ) ) {
    os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner:operating_system, banner_type:"mDNS banner", port:port, proto:"udp", desc:"mDNS Service Detection", runs_key:"windows" );
  } else if( "mac os x" >< tolower( operating_system ) ) {
    os_register_and_report( os:"Mac OS X", cpe:"cpe:/o:apple:mac_os_x", banner:operating_system, banner_type:"mDNS banner", port:port, proto:"udp", desc:"mDNS Service Detection", runs_key:"unixoide" );
  } else {
    os_register_unknown_banner( banner:operating_system, banner_type_name:"mDNS banner", banner_type_short:"mdns_banner", port:port, proto:"udp" );
  }
}

if( strlen( report ) ) {
  log_message( port:port, data:chomp( report ), protocol:"udp" );
}

exit( 0 );
