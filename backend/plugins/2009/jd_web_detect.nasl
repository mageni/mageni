###############################################################################
# OpenVAS Vulnerability Test
# $Id: jd_web_detect.nasl 10727 2018-08-02 08:33:07Z cfischer $
#
# JDownloader Web Detection
#
# Authors:
# Michael Meyer
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
  script_oid("1.3.6.1.4.1.25623.1.0.100301");
  script_version("$Revision: 10727 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-02 10:33:07 +0200 (Thu, 02 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-11 19:51:15 +0200 (Sun, 11 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("JDownloader Web Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8765, 9666);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://jdownloader.org");

  script_tag(name:"summary", value:"JDownloader is running at this port. JDownloader is open
  source, platform independent and written completely in Java. It simplifies downloading files
  from One-Click-Hosters like Rapidshare.com or Megaupload.com.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8765 );
host = http_host_name( dont_add_port:TRUE );

url = "/";
buf = http_get_cache( item:url, port:port );
if( isnull( buf ) ) exit( 0 );
banner = get_http_banner( port:port );

if( 'WWW-Authenticate: Basic realm="JDownloader' >< banner ) {

  JD = TRUE;
  JD_WEBINTERFACE = TRUE;
  set_kb_item( name:"www/" + host + "/" + port + "/password_protected", value:TRUE );

  userpass  = string( "JD:JD" ); # default pw
  userpass64 = base64( str:userpass );
  req = string( "GET / HTTP/1.0\r\n",
                "Authorization: Basic ", userpass64 ,
                "\r\n\r\n" );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf ) {
    if( "JDownloader - WebInterface" >< buf ) {
      DEFAULT_PW = TRUE;
      set_kb_item( name:"www/" + host + "/" + port + "/jdwebinterface/default_pw", value:TRUE );
      version = eregmatch( pattern:"Webinterface-([0-9]+)", string:buf );
    }
  }
} else if( "JDownloader - WebInterface" >< buf ) {
  JD = TRUE;
  JD_WEBINTERFACE = TRUE;
  JD_UNPROTECTED = TRUE;
  version = eregmatch( pattern:"Webinterface-([0-9]+)", string:buf );
}

if( "Server: jDownloader" >< banner ) {
  concl = egrep( pattern:"^Server: jDownloader", string:banner );
  JD = TRUE;
  JD_WEBSERVER = TRUE;
  set_kb_item( name:"www/" + host + "/" + port + "/jdwebserver", value:TRUE );
}

if( JD ) {
  if( JD_WEBINTERFACE ) {
    if( version && ! isnull( version[1] ) ) {
      vers = version[1];
    } else {
      vers = "unknown";
    }

    set_kb_item( name:"www/" + host + "/" + port + "/jdwebinterface", value:vers );

    if( JD_UNPROTECTED ) {
      info += string("\nJDownloader Webinterface is *not* protected by password.\n");
    } else if( DEFAULT_PW ) {
      # TBD: Write a separate Vuln-NVT for this?
      info += string("\nIt was possible to log in into the JDownloader Webinterface\nby using 'JD' (the default username and password) as username and password.\n");
    }

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:jdownloader:jdownloader_webgui:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:jdownloader:jdownloader_webgui";

    register_product( cpe:cpe, location:url, port:port );

    report = build_detection_report( app:"JDownloader Webinterface",
                                     version:version,
                                     install:url,
                                     cpe:cpe,
                                     extra:info,
                                     concluded:version[0] );
  }

  if( JD_WEBSERVER ) {

    if( JD_WEBINTERFACE )
      report += '\n\n';

    install = port + "/tcp";
    version = "unknown";
    cpe = "cpe:/a:jdownloader:jdownloader_webserver";

    register_product( cpe:cpe, location:install, port:port );

    report += build_detection_report( app:"JDownloader Webserver",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concluded:chomp( concl ) );
  }
  log_message( port:port, data:report );
}

exit( 0 );
