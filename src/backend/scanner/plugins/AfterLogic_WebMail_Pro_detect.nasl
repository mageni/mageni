###############################################################################
# OpenVAS Vulnerability Test
# $Id: AfterLogic_WebMail_Pro_detect.nasl 13977 2019-03-04 10:00:10Z cfischer $
#
# AfterLogic WebMail Pro Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100313");
  script_version("$Revision: 13977 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 11:00:10 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-10-20 18:54:22 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("AfterLogic WebMail Pro Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running AfterLogic WebMail Pro, a Webmail front-end for your
  existing POP3/IMAP mail server.");

  script_xref(name:"URL", value:"http://www.afterlogic.com/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

# Choose file to request based on what the remote host is supporting
if( can_host_asp( port:port ) && can_host_php( port:port ) ) {
  files = make_list( "/index.php", "/default.aspx" );
} else if( can_host_asp( port:port ) ) {
  files = make_list( "/default.aspx" );
} else if( can_host_php( port:port ) ) {
  files = make_list( "/index.php" );
} else {
  exit( 0 );
}

foreach dir( make_list_unique( "/webmail", "/mail", "/email", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach file( files ) {

    url = dir + file;
    buf = http_get_cache( item:url, port:port );
    if( !buf ) continue;

    if( egrep( pattern:"Powered by.*AfterLogic WebMail Pro", string:buf, icase:TRUE ) ) {

      vers = "unknown";
      version = eregmatch( string:buf, pattern:"<!--[^0-9]*([0-9.]+)[^-]*-->", icase:TRUE );
      if( ! isnull( version[1] ) )
        vers = chomp( version[1] );

      set_kb_item( name:"AfterLogicWebMailPro/installed", value:TRUE );

      cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:afterlogic:mailbee_webmail_pro:" );
      if( isnull( cpe ) )
        cpe = "cpe:/a:afterlogic:mailbee_webmail_pro";

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"AfterLogic WebMail Pro",
                                                version:vers,
                                                install:install,
                                                cpe:cpe,
                                                concluded:version[0] ),
                   port:port );
      exit( 0 );
    }
  }
}

exit( 0 );