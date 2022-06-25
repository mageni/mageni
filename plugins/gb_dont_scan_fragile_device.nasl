###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dont_scan_fragile_device.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Do not scan fragile devices or ports
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108298");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-11-24 14:08:04 +0100 (Fri, 24 Nov 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Do not scan fragile devices or ports");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Settings");
  script_dependencies("global_settings.nasl");
  script_mandatory_keys("global_settings/exclude_fragile");

  script_add_preference(name:"Exclude specific port(s) from scan", type:"entry", value:"");

  script_tag(name:"summary", value:"This script checks if the remote host is a 'fragile' device
  known to be crashing / showing an unexpected behavior if scanned. It will output more info
  if a specific port or the whole device was excluded from the scan.

  Additionally the 'Exclude specific port(s) from scan' script preference allows to specify own ports
  to be exclude from the scan with the following syntax:

  5060:all:full,443:tcp:tlsonly

  where the following is allowed:

  5060 - portnumber between 1 and 65535

  all  - transport protocol of the port. Currently available options: all, tcp, udp

  full - how the port should be excluded. full: the port is excluded from all checks including SSL/TLS tests,
  tlsonly: the port is only excluded from SSL/TLS checks,
  nottls: the port is excluded from all checks except SSL/TLS. Currently available options: full, nottls, tlsonly

  It is possible to disable this behavior by setting the preference 'Exclude known fragile devices/ports from scan'
  within the 'Global variable settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) to 'no'.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");
include("telnet_func.inc");
include("misc_func.inc");

if( get_kb_item( "Host/scanned" ) == 0 ) exit( 0 );
if( ! get_kb_item( "global_settings/exclude_fragile" ) ) exit( 0 );

function check_and_apply_exclude_port_definition( exclude_port_definition ) {

  local_var exclude_port_definition, _split_list, _split_line, _error;
  local_var _split_item, _port, _proto, _tests, exclude_from_tls, only_exclude_from_tls;

  _split_list = split( exclude_port_definition, sep:",", keep:FALSE );
  foreach _split_line( _split_list ) {
    if( ! egrep( string:_split_line, pattern:"^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]):(all|tcp|udp):(full|nottls|tlsonly)$" ) ) {
      _error += _split_line + '\n';
      continue;
    }
    _split_item = split( _split_line, sep:":", keep:FALSE );
    _port  = _split_item[0];
    _proto = _split_item[1];
    _tests = _split_item[2];
    if( _tests == "full" ) {
      exclude_from_tls      = TRUE;
      only_exclude_from_tls = FALSE;
    } else if( _tests == "nottls" ) {
      exclude_from_tls      = FALSE;
      only_exclude_from_tls = FALSE;
    } else if( _tests == "tlsonly" ) {
      exclude_from_tls      = TRUE;
      only_exclude_from_tls = TRUE;
    }
    fragile_exclude_and_report( reason:"- " + _split_line + " ", port:_port, proto:_proto, exclude_from_tls:exclude_from_tls, only_exclude_from_tls:only_exclude_from_tls, selfdefined:TRUE );
  }

  if( _error ) {
    log_message( port:0, data:'Wrong syntax in the following line(s) of the "Exclude specific port(s) from scan" preference:\n\n' + _error );
  }
}

# nb: exclude_from_tls is causing that the port is not even touched by SSL/TLS tests,
# only_exclude_from_tls that it is only excluded from the SSL/TLS tests.
function fragile_exclude_and_report( reason, port, proto, mark_dead, exclude_from_tls, only_exclude_from_tls, selfdefined ) {

  local_var reason, port, proto, mark_dead, exclude_from_tls, only_exclude_from_tls, selfdefined;
  local_var exclude_port_text, mark_dead_text, enable_text, _proto;

  exclude_port_text = 'This port was excluded from the scan because of the following reason:\n\n';
  mark_dead_text    = 'The scan has been disabled against this host because of the following reason:\n\n';
  enable_text       = '\n\nIf you want to disable this behavior please set the preference "Exclude known fragile devices/ports from scan" ';
  enable_text      += ' within the "Global variable settings" (OID: 1.3.6.1.4.1.25623.1.0.12288) to "no".';
  selfdefined_text  = 'configuration via the "Exclude specific port(s) from scan" preference of this script.';

  if( selfdefined ) {
    if( proto == "tcp" ) {
      if( get_port_state( port ) ) {
        if( exclude_from_tls ) set_kb_item( name:"fragile_port/exclude_tls/" + port, value:TRUE );
        if( ! only_exclude_from_tls ) {
          register_service( port:port, proto:"fragile_port", ipproto:proto );
          replace_kb_item( name:"BannerHex/" + port, value:"aeaeaeaeae" );
          replace_kb_item( name:"Banner/" + port, value:"ignore-this-banner" );
        }
        log_message( port:port, data:exclude_port_text + reason + selfdefined_text, proto:proto );
        return;
      }
    } else if( proto == "udp" ) {
      if( get_udp_port_state( port ) ) {
        register_service( port:port, proto:"fragile_port", ipproto:proto );
        log_message( port:port, data:exclude_port_text + reason + selfdefined_text, proto:proto );
        return;
      }
    } else if( proto == "all" ) {
      foreach _proto( make_list( "udp", "tcp" ) ) {
        if( _proto == "udp" ) {
          if( get_udp_port_state( port ) ) {
            register_service( port:port, proto:"fragile_port", ipproto:_proto );
            log_message( port:port, data:exclude_port_text + reason + selfdefined_text, proto:_proto );
          }
        } else {
          if( get_port_state( port ) ) {
            if( exclude_from_tls ) set_kb_item( name:"fragile_port/exclude_tls/" + port, value:TRUE );
            if( ! only_exclude_from_tls ) {
              register_service( port:port, proto:"fragile_port", ipproto:_proto );
              replace_kb_item( name:"BannerHex/" + port, value:"aeaeaeaeae" );
              replace_kb_item( name:"Banner/" + port, value:"ignore-this-banner" );
            }
            log_message( port:port, data:exclude_port_text + reason + selfdefined_text, proto:_proto );
           }
        }
      }
    }
    return;
  }

  if( mark_dead ) {
    log_message( data:mark_dead_text + reason + enable_text );
    set_kb_item( name:"Host/dead", value:TRUE );
    exit( 0 );
  }

  if( get_port_state( port ) ) {
    if( exclude_from_tls ) set_kb_item( name:"fragile_port/exclude_tls/" + port, value:TRUE );
    register_service( port:port, proto:"fragile_port" );
    replace_kb_item( name:"BannerHex/" + port, value:"aeaeaeaeae" );
    replace_kb_item( name:"Banner/" + port, value:"ignore-this-banner" );
    log_message( port:port, data:exclude_port_text + reason + enable_text );
    # nb: This  exit needs to be replaced by a return once more different devices are added down below.
    # consider to merge this method with the one above and only set a different text based on the "selfdefined"
    exit( 0 );
  }
}

exclude_port_definition = script_get_preference( "Exclude specific port(s) from scan" );

if( strlen( exclude_port_definition ) > 0 ) {
  check_and_apply_exclude_port_definition( exclude_port_definition:exclude_port_definition );
}

# Lantronix devices on telnet 9999/tcp
# This device is known to break if port 30718/tcp is touched
port = 9999;
if( get_port_state( port ) ) {
  banner = get_telnet_banner( port:port );
  if( banner && ( banner =~ "Lantronix .* Device Server" || ( "MAC address " >< banner && "Software version " >< banner ) ) ) {
    fragile_exclude_and_report( reason:"- The detected Lantronix Device is known to crash if this port is scanned.", port:30718, exclude_from_tls:TRUE );
  }
}

# Same Lantronix devices above but check directly 30718/udp
port = 30718;
if( get_udp_port_state( port ) ) {
  soc = open_sock_udp( port );
  if( soc ) {
    req = raw_string( 0x00, 0x00, 0x00, 0xF8 );
    send( socket:soc, data:req );
    recv = recv( socket:soc, length:124 );
    close( soc );
    if( recv && strlen( recv ) == 124 && hexstr( substr( recv, 0, 3 ) ) == "000000f9" ) {
      fragile_exclude_and_report( reason:"- The detected Lantronix Device is known to crash if this port is scanned.", port:30718, exclude_from_tls:TRUE );
    }
  }
}

# And the same for 30718/tcp
port = 30718;
if( get_port_state( port ) ) {
  soc = open_sock_tcp( port );
  if( soc ) {
    req = raw_string( 0x00, 0x00, 0x00, 0xF8 );
    send( socket:soc, data:req );
    recv = recv( socket:soc, length:124 );
    close( soc );
    if( recv && strlen( recv ) == 124 && hexstr( substr( recv, 0, 3 ) ) == "000000f9" ) {
      fragile_exclude_and_report( reason:"- The detected Lantronix Device is known to crash if this port is scanned.", port:30718, exclude_from_tls:TRUE );
    }
  }
}

# Devices running Nucleus RTOS on ftp 21/tcp
port = 21;
if( get_port_state( port ) ) {
  banner = get_ftp_banner( port:port );
  if( banner && ( banner =~ "220 Nucleus FTP Server \(Version [0-9.]+\) ready" ) ) {
    fragile_exclude_and_report( reason: "- The detected device running Nucleus RTOS is known to crash if this port is scanned.", port:21, exclude_from_tls:TRUE );
  }
}

exit( 0 );