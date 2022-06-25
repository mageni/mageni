###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_canon_printers_detect.nasl 10899 2018-08-10 13:49:35Z cfischer $
#
# Canon Printer Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.803719");
  script_version("$Revision: 10899 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:49:35 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2013-06-20 13:42:47 +0530 (Thu, 20 Jun 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Canon Printer Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  # nb: Don't use http_version.nasl as the Detection should run as early
  # as possible if the printer should be marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Canon Printers.

  The script sends a connection request to the remote host and
  attempts to detect if the remote host is a Canon printer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
buf  = http_get_cache( item:"/index.html", port:port );
buf2 = http_get_cache( item:"/", port:port );

# If updating here please also update the check in dont_print_on_printers.nasl
if( ( '>Canon' >< buf && ">Copyright CANON INC" >< buf && "Printer" >< buf ) ||
    "CANON HTTP Server" >< buf || ( "erver: Catwalk" >< buf2 && "com.canon.meap.service" >< buf2 ) ||
    ( (('canonlogo.gif" alt="CANON"' >< buf2) || ('canonlogo.gif" alt=' >< buf2) || ("canonlogo.gif" >< buf2 && "Series</title>" >< buf2)) &&
       ">Copyright CANON INC" >< buf2 ) )
{
  set_kb_item( name:"target_is_printer", value:TRUE );
  set_kb_item( name:"canon_printer/installed", value:TRUE );
  set_kb_item( name:"canon_printer/port", value:port );

  printer_model = eregmatch( pattern:">(Canon.[A-Z0-9]+).[A-Za-z]+<", string:buf );
  if( printer_model[1] ) {
    model = printer_model[1];
    set_kb_item( name:"canon_printer_model", value:model );
    cpe_printer_model = tolower( model );
    cpe = "cpe:/h:canon:" + cpe_printer_model;
    cpe = str_replace( string:cpe, find:" ", replace:"_" );
  }

  if( ! model ) {
    # <span id="deviceName">MF210&nbsp;Series&nbsp;-&nbsp;Admin&nbsp;office / MF210 Series / </span>
    printer_model = eregmatch( pattern:'<span id="deviceName".* / ([A-Za-z0-9 ]+) / ', string:buf2 );
    if(!printer_model[1] )
    {
      # <span id="deviceName">iR-ADV C3330  / iR-ADV C3330 /  </span>
      # <span id="deviceName">iR-ADV C5235 - JWC04988  / iR-ADV C5235 /  VIetnam</span>
      # <span id="deviceName">iR-ADV C5255  / iR-ADV C5255 /  </span>
      # <span id="deviceName">iR-ADV 8595 / iR-ADV 8595 / </span>
      printer_model = eregmatch( pattern:'<span id="deviceName">([^/<]+)', string:buf2 );
    }
    if( printer_model[1] )
    {
      ##Remove Non-Breaking SPace
      if("&nbsp;" >< printer_model[1]){
        canon_model = ereg_replace(pattern:"&nbsp;", replace:" ", string:printer_model[1]);
      } else {
        canon_model =  printer_model[1] ;
      }

      model = chomp( canon_model );

      set_kb_item( name:"canon_printer_model", value:model );
      cpe_printer_model = tolower( model );
      cpe = "cpe:/h:canon:" + cpe_printer_model;
      cpe = str_replace( string:cpe, find:" ", replace:"_" );
    }
  }

  if( ! model ) {
    model = "Unknown Canon model";
    cpe = "cpe:/h:canon:unknown_model";
  }

  firm_ver = eregmatch( pattern:"nowrap>([0-9.]+)</td>", string:buf );
  if( firm_ver[1] ) {
    set_kb_item( name:"canon_printer/firmware_ver", value:firm_ver[1] );
    cpe = cpe + ":" + firm_ver[1];
  }

  register_product( cpe:cpe, location:port + "/tcp", port:port );
  log_message(data:build_detection_report(app:"Canon " + model + " Printer Device",
                                            version: firm_ver[1],
                                            install:port + "/tcp",
                                            cpe:cpe,
                                            concluded:printer_model[0]));

  pref = get_kb_item( "global_settings/exclude_printers" );
  if( pref == "yes" ) {
    log_message( port:port, data:'The remote host is a printer. The scan has been disabled against this host.\nIf you want to scan the remote host, uncheck the "Exclude printers from scan" option and re-scan it.');
    set_kb_item( name:"Host/dead", value:TRUE );
  }
}
exit( 0 );
