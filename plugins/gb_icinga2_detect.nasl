###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icinga2_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Icinga 2 Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113120");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-03-01 13:53:44 +0100 (Thu, 01 Mar 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Icinga 2 Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 5665);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks for the presence and version of Icinga 2 on the target host
  (Providing Icinga2 API Credentials can lead to better results).");

  script_add_preference(name:"API Username", value:"", type:"entry");
  script_add_preference(name:"API Password", value:"", type:"password");

  script_xref(name:"URL", value:"https://www.icinga.com/products/icinga-2/");
  script_xref(name:"URL", value:"https://www.icinga.com/docs/icinga2/latest/doc/12-icinga2-api/");

  exit(0);
}

include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "host_details.inc" );
include( "cpe.inc" );
include( "misc_func.inc" );

port = get_http_port( default:5665 );
banner = get_http_banner( port: port );
detected = FALSE;

# Server: Icinga/r2.8.1-1
# Server: Icinga/r2.7.1-1
if( "erver: Icinga" >< banner || 'Basic realm="Icinga 2"' >< banner ) {
  install  = "/";
  version  = "unknown";
  detected = TRUE;
  vers     = eregmatch( string: banner, pattern: "Icinga/r?([0-9.-]+)" );
  if( ! isnull( vers[1] ) ) version = vers[1];
}

if( detected && version == "unknown" ) {

  user = script_get_preference( "API Username" );
  pass = script_get_preference( "API Password" );

  if( ! user && ! pass ) {
    extra = "Incinga 2 Detected but version unknown. Providing API credentials to this NVT might allow to gather the version.";
  } else if( ! user && pass ) {
    log_message( data: "Password provided but Username is missing.", port: port );
  } else if( user && ! pass ) {
    log_message( data: "Username provided but Password is missing.", port: port );
  } else if( user && pass ) {
    url = "/v1/status/IcingaApplication";
    add_headers = make_array( "Authorization", "Basic " + base64( str: user + ":" + pass ) );
    req = http_get_req( port: port, url: url, add_headers: add_headers, accept_header: "*/*");
    res = http_keepalive_send_recv( port: port, data: req );
    if( res =~ "^HTTP/1\.[01] 200" && '{"results":' >< res ) {
      vers = eregmatch( string: res, pattern: '"version":"r?([0-9.-]+)"' );
      if( ! isnull( vers[1] ) ) {
        version  = vers[1];
        conclUrl = url;
      }
    } else {
      log_message( data: 'Username and Password provided but login to the API failed with the following response:\n\n' + res, port: port );
    }
  }
}

if( ! detected ) exit( 0 );

set_kb_item( name: "icinga2/detected", value: TRUE );

register_and_report_cpe( app: "Icinga 2",
                         ver: version,
                         insloc: install,
                         concluded: vers[0],
                         base: "cpe:/a:icinga:icinga2:",
                         expr: "([r0-9.-]+)",
                         conclUrl: conclUrl,
                         regPort: port,
                         extra: extra );

exit( 0 );
