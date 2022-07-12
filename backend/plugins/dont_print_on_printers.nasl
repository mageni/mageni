###############################################################################
# OpenVAS Vulnerability Test
#
# Do not print on AppSocket and socketAPI printers
#
# Authors:
# Laurent Facq <facq@u-bordeaux.fr> 05/2004
# 99% based on dont_scan_printers by Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 by Laurent Facq
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
  script_oid("1.3.6.1.4.1.25623.1.0.12241");
  script_version("2019-04-17T12:18:39+0000");
  script_tag(name:"last_modification", value:"2019-04-17 12:18:39 +0000 (Wed, 17 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Do not print on AppSocket and socketAPI printers");
  script_category(ACT_SETTINGS);
  script_copyright("This script is Copyright (C) 2005 by Laurent Facq");
  script_family("Settings");
  script_dependencies("gb_snmp_sysdesc.nasl", "nmap_mac.nasl", "global_settings.nasl");

  script_add_preference(name:"Exclude PJL printer ports from scan", type:"entry", value:"9100,9101,9102,9103,9104,9105,9106,9107,9112,9113,9114,9115,9116");

  script_tag(name:"summary", value:"The host seems to be an AppSocket or socketAPI printer.
  Scanning it will waste paper. So ports 9100-9107 & 9112-9116 won't be scanned by default.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");
include("telnet_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("mac_prefix.inc");
include("hp_printers.inc");
include("sharp_printers.inc");
include("kyocera_printers.inc");
include("lexmark_printers.inc");
include("xerox_printers.inc");
include("snmp_func.inc");

pjl_ports_list = make_list();

function check_pjl_port_list( list ) {

  local_var list, ports, port;

  if( ! list ) return FALSE;

  ports = split( list, sep:",", keep:FALSE );

  foreach port( ports ) {

    if( ! ereg( pattern:"^[0-9]{1,5}$", string:port ) ) {
      return FALSE;
    }
    if( int( port ) > 65535 ) return FALSE;
  }
  return TRUE;
}

function report( data ) {

  local_var data, port;

  register_all_pjl_ports( ports:pjl_ports_list );
  if( ! invalid_list ) {
    foreach port( pjl_ports_list ) {
      if( get_port_state( port ) ) {
        log_message( port:port, data:"This port was excluded from the scan to avoid printing out paper on this printer during a scan." );
      }
    }
  }

  log_message( port:0, data:'Exclusion reason:\n\n' + data );
  set_kb_item( name:"Host/is_printer/reason", value:data );
  set_kb_item( name:"Host/is_printer", value:TRUE );
  exit( 0 );
}

is_printer = FALSE;

if( get_kb_item( "Host/scanned" ) == 0 ) exit( 0 );

pjl_ports = script_get_preference( "Exclude PJL printer ports from scan" );

if( strlen( pjl_ports ) > 0 ) {
  pjl_ports = str_replace( string:pjl_ports, find:" ", replace:"" );
  if( ! check_pjl_port_list( list:pjl_ports ) ) {
    report = '"Exclude PJL printer ports from scan" has wrong format or contains an invalid port and was ignored. Please use a\ncomma separated list of ports without spaces. Example: 9100,9101,9102,9103,9104,9105,9106,9107,9112,9113,9114,9115,9116\n\n';
    report += 'The following default ports were excluded from the scan to avoid printing out paper on this printer during a scan:\n\n9100,9101,9102,9103,9104,9105,9106,9107,9112,9113,9114,9115,9116';
    invalid_list = TRUE;
    log_message( port:0, data:report );
    pjl_ports_list = make_list( 9100, 9101, 9102, 9103, 9104, 9105, 9106, 9107, 9112, 9113, 9114, 9115, 9116 );
  } else {
    pjl_report = pjl_ports;
    ports = split( pjl_ports, sep:",", keep:FALSE );
    foreach port( ports ) {
      pjl_ports_list = make_list( pjl_ports_list, port );
    }
  }
} else {
  pjl_report = "9100,9101,9102,9103,9104,9105,9106,9107,9112,9113,9114,9115,9116";
  pjl_ports_list = make_list( 9100, 9101, 9102, 9103, 9104, 9105, 9106, 9107, 9112, 9113, 9114, 9115, 9116 );
}

# First try SNMP on default 161
port = 161;
if( sysdesc = get_snmp_sysdesc( port:port ) ) {

  # xerox
  if( "Xerox WorkCentre" >< sysdesc ||
      "XEROX DocuCentre" >< sysdesc ||
      "XEROX DocuPrint"  >< sysdesc ||
      "XEROX Document Centre" >< sysdesc ||
      "Xerox Phaser" >< sysdesc ) {
    is_printer = TRUE;
  }

  # canon
  if( sysdesc =~ "^Canon[^/]+/P" ||
      "Canon LBP" >< sysdesc ) {
    is_printer = TRUE;
  }

  # KYOCERA
  if( ( sysdesc =~ "^KYOCERA" && "Print" >< sysdesc ) ) {
    is_printer = TRUE;
  }

  # Lexmark
  if( sysdesc =~ '^Lexmark.*version.*kernel' ) {
    is_printer = TRUE;
  }

  # sharp
  if( sysdesc =~ '^SHARP (MX|AR)' ) {
    is_printer = TRUE;
  }
}

if( is_printer ) report( data:"Detected SNMP SysDesc on port " + port + '/udp:\n\n' + sysdesc );

# UDP AppSocket
port = 9101;
if( get_udp_port_state( port ) ) {

  soc = open_sock_udp( port );

  send( socket:soc, data:'\r\n' );
  r = recv( socket:soc, length:512 );
  close( soc );
  if( r ) {
    is_printer = TRUE;
  }
}

if( is_printer ) report( data:"Detected UDP AppSocket on port " + port + '/udp' );

#TBD: Also test 9101-9107 & 9112-9116?
#The ( ! r && se == ETIMEDOUT ) might cause false positives here
port = 9100;
if( get_port_state( port ) ) {

  soc = open_sock_tcp( port );

  if( soc ) {
    send( socket:soc, data:'\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n' );
    r = recv( socket:soc, length:512 );
    se = socket_get_error( soc );
    close( soc );
    if( "@PJL" >< r || ( ! r && se == ETIMEDOUT ) ) {
      is_printer = TRUE;
    }
  }
}

if( is_printer ) report( data:"Detected PJL service on port " + port + '/tcp' );

port = 21;
if( get_port_state( port ) ) {

  banner = get_ftp_banner( port:port );

  if("JD FTP Server Ready" >< banner) {
    is_printer = TRUE;
  } else if ("220 Dell Laser Printer " >< banner) {
    is_printer = TRUE;
  } else if ("220 RICOH Aficio " >< banner) {
    is_printer = TRUE;
  } else if ("220 FTP print service" >< banner) {
    is_printer = TRUE;
  } else if ("220 KONICA MINOLTA" >< banner) {
    is_printer = TRUE;
  } else if ("220 Xerox" >< banner) {
    is_printer = TRUE;
  } else if ("FUJI XEROX" >< banner) {
    is_printer = TRUE;
  }
}

if( is_printer ) report( data:"Detected FTP banner on port " + port + '/tcp:\n\n' + banner );

port = 23;
if( get_port_state( port ) ) {

  banner = get_telnet_banner( port:port );

  if( "HP JetDirect" >< banner ) {
    is_printer = TRUE;
  } else if ("RICOH Maintenance Shell." >< banner) {
    is_printer = TRUE;
  } else if ("Welcome. Type <return>, enter password at # prompt" >< banner) {
    is_printer = TRUE;
  }
}

if( is_printer ) report( data:"Detected Telnet banner on port " + port + '/tcp:\n\n' + banner );

# Xerox DocuPrint
port = 2002;
if( get_port_state( port ) ) {

  soc = open_sock_tcp( port );
  if( soc ) {
    banner = recv( socket:soc, length:23 );
    close( soc );
    if( banner && 'Please enter a password' >< banner ) {
      is_printer = TRUE;
    }
  }
}

if( is_printer ) report( data:"Detected Xerox DocuPrint banner on port " + port + '/tcp:\n\n' + banner );

if( mac = get_kb_item( "Host/mac_address" ) ) {
  if( is_printer_mac( mac:mac ) )
    is_printer = TRUE;
}

if( is_printer ) report( data:"Detected MAC-Address of a Printer-Vendor: " + mac );

# Keep the HTTP check at the bottom as this can take quite some time
konica_detect_urls = make_array();
konica_detect_urls['/wcd/top.xml'] = '301 Movprm';
konica_detect_urls['/wcd/system_device.xml'] = '301 Movprm';
konica_detect_urls['/wcd/system.xml'] = '301 Movprm';

# Patch by Laurent Facq
ports = make_list( 80, 8000, 280, 631 ); # TODO: Re-add 443 and add 8443 once a solution was found to detect SSL/TLS without a dependency to find_service.nasl

foreach port( ports ) {

  if( ! get_port_state( port ) ) continue;

  # Sharp can be detected from the banner, see also gb_sharp_printer_detect.nasl
  # If updating here please also update check gb_sharp_printer_detect.nasl
  banner = get_http_banner( port:port );
  if( "Extend-sharp-setting-status" >< banner && "Server: Rapid Logic" >< banner ) {
    is_printer = TRUE;
    reason     = "Sharp Banner/Text on port " + port + "/tcp: " + banner;
    break;
  }

  # Canon, see also gb_canon_printers_detect.nasl
  # If updating here please also update the check in gb_canon_printers_detect.nasl
  url = "/index.html";
  buf = http_get_cache( item:url, port:port );
  if( ( '>Canon' >< buf && ">Copyright CANON INC" >< buf && "Printer" >< buf ) || "CANON HTTP Server" >< banner ) {
    is_printer = TRUE;
    reason     = "Canon Banner/Text on URL: " + report_vuln_url( port:port, url:url, url_only:TRUE );
    break;
  }
  url = "/";
  buf = http_get_cache( item:url, port:port );
  if( ( "erver: Catwalk" >< buf && "com.canon.meap.service" >< buf ) ||
      ( ( ( 'canonlogo.gif" alt="CANON"' >< buf ) || ( 'canonlogo.gif" alt=' >< buf ) || ( "canonlogo.gif" >< buf && "Series</title>" >< buf ) ) &&
       ">Copyright CANON INC" >< buf ) ) {
    is_printer = TRUE;
    reason     = "Canon Banner/Text on URL: " + report_vuln_url( port:port, url:url, url_only:TRUE );
    break;
  }

  # Brother HL Printer from gb_brother_hl_series_printer_detect.nasl
  # If updating here please also update the check in gb_brother_hl_series_printer_detect.nasl
  buf = http_get_cache( item:"/general/information.html?kind=item", port:port );
  if( buf =~ "<title>Brother HL.*series</title>" && buf =~ "Copyright.*Brother Industries" ) {
    is_printer = TRUE;
    reason     = "Brother Banner/Text on URL: " + report_vuln_url( port:port, url:url, url_only:TRUE );
    break;
  }

  # Konica Minolta TODO: Move to own printer detect NVT
  foreach url( keys( konica_detect_urls ) ) {

    buf = http_get_cache( item:url, port:port );

    if( eregmatch( pattern:konica_detect_urls[url], string:buf, icase:TRUE ) ) {
      is_printer = TRUE;
      reason     = "Found pattern: " + konica_detect_urls[url] + " on URL: " + report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }

  if( is_printer ) break;

  # HP, see also gb_hp_printer_detect.nasl
  urls = get_hp_detect_urls();
  foreach url( keys( urls ) ) {

    buf = http_get_cache( item:url, port:port );

    if( eregmatch( pattern:urls[url], string:buf, icase:TRUE ) ) {
      is_printer = TRUE;
      reason     = "Found pattern: " + urls[url] + " on URL: " + report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }

  if( is_printer ) break;

  # Kyocera, see also gb_kyocera_printers_detect.nasl
  urls = get_ky_detect_urls();
  foreach url( keys( urls ) ) {

    buf = http_get_cache( item:urls[url], port:port );

    if( eregmatch( pattern:url, string:buf, icase:TRUE ) ) {
      is_printer = TRUE;
      reason     = "Found pattern: " + urls[url] + " on URL: " + report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }

  if( is_printer ) break;

  # Lexmark, see also gb_lexmark_printers_detect.nasl
  urls = get_lexmark_detect_urls();
  foreach url( keys( urls ) ) {

    buf = http_get_cache( item:urls[url], port:port );

    if( eregmatch( pattern:url, string:buf, icase:TRUE ) ) {
      is_printer = TRUE;
      reason     = "Found pattern: " + urls[url] + " on URL: " + report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }

  if( is_printer ) break;

  # Xerox, see also gb_xerox_printer_detect.nasl
  urls = get_xerox_detect_urls();
  foreach url( keys( urls ) ) {

    buf = http_get_cache( item:url, port:port );

    if( eregmatch( pattern:urls[url], string:buf, icase:TRUE ) ) {
      is_printer = TRUE;
      reason     = "Found pattern: " + urls[url] + " on URL: " + report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }

  if( is_printer ) break;

  # TODO: Re-verify these URLs and the banners below
  foreach url( make_list( "/", "/main.asp", "/index.asp",
                          "/index.html", "/index.htm", "/default.html" ) ) {

    buf = http_get_cache( item:url, port:port );

    # Dell
    if( "Dell Laser Printer " >< banner || "Server: EWS-NIC5/" >< banner || "Dell Laser MFP " >< banner ) {
      is_printer = TRUE;
      reason     = "Dell Banner on port " + port + "/tcp: " + banner;
      break;
    # TBD: unknown printers. Ricoh?
    } else if( banner && "Server: GoAhead-Webs" >< banner && "Aficio SP" >< banner || "<title>Web Image Monitor</title>" >< banner ) {
      is_printer = TRUE;
      reason     = "Printer Banner on port " + port + "/tcp: " + banner;
      break;
    # Old HP banner check
    } else if( "<title>Hewlett Packard</title>" >< buf || egrep( pattern:"<title>.*LaserJet.*</title>", string:buf, icase:TRUE ) ||
               "HP Officejet" >< buf || "server: hp-chai" >< tolower( buf ) || ( "Server: Virata-EmWeb/" >< buf && ( "HP" >< banner || "printer" >< buf ) ) ) {
      is_printer = TRUE;
      reason     = "HP Banner/Text on URL: " + report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    # Old Xerox banner check
    } else if( "Server: Xerox_MicroServer/Xerox" >< buf || "Server: EWS-NIC" >< buf || "<title>DocuPrint" >< buf || "<title>Phaser" >< buf ||
               ( "XEROX WORKCENTRE" >< buf && "Xerox Corporation. All Rights Reserved." >< buf ) || ( "DocuCentre" >< buf && "Fuji Xerox Co., Ltd." >< buf ) ) {
      is_printer = TRUE;
      reason     = "Xerox Banner/Text on URL: " + report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }
  if( is_printer ) break;
}

if( is_printer ) report( data:reason );

exit( 0 );

# TBD if the following should be still used
#
# open ports?
#ports = get_kb_list("Ports/tcp/*");
#
# Host is dead, or all ports closed, or unscanned => cannot decide
#if (isnull(ports)) exit(0);
# Ever seen a printer with more than 8 open ports?
# if (max_index(ports) > 8) exit(0);

# Test if open ports are seen on a printer
# http://www.lprng.com/LPRng-HOWTO-Multipart/x4981.htm
#appsocket = 0;
#
#foreach p (keys(ports))
#{
#  p = int(p - "Ports/tcp/");
#  if (	   p == 35                  # AppSocket for QMS
#       || p == 2000                # Xerox
#       || p == 2501                # AppSocket for Xerox
#       || (p >= 3001 && p <= 3005) # Lantronix - several ports
#       || (p >= 9100 && p <= 9300) # AppSocket - several ports
#       || p == 10000               # Lexmark
#       || p == 10001)              # Xerox - programmable :-(
#    appsocket = 1;
# Look for common non-printer ports
#	 else if (
#          p != 21              # FTP
#       && p != 23              # telnet
#       && p != 79
#       && p != 80              # www
#       && p != 139 && p!= 445  # SMB
#       && p != 280             # http-mgmt
#       && p != 443
#       && p != 515             # lpd
#       && p != 631 	       # IPP
#       && p != 8000
#       && (p < 5120 || p > 5129))  # Ports 512x are used on HP printers
#	exit(0);
#
#}
#
# OK, this might well be an AppSocket printer
#if (appsocket)
#{
#  log_message(0);
#
#  register_service(port: 9100, proto: "ignore-this-printer-port");
#
#  #set_kb_item( name:"Host/dead", value:TRUE );
#}
