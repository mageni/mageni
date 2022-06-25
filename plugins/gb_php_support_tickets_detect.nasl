###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_support_tickets_detect.nasl 10321 2018-06-26 06:01:09Z cfischer $
#
# PHP Support Tickets Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103255");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10321 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-26 08:01:09 +0200 (Tue, 26 Jun 2018) $");
  script_tag(name:"creation_date", value:"2011-09-14 13:31:57 +0200 (Wed, 14 Sep 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("PHP Support Tickets Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.phpsupporttickets.com/");

  script_tag(name:"summary", value:"This host is running PHP Support Tickets, a PHP5 / MySQL helpdesk
  system.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/tickets", "/support", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( isnull( buf ) ) continue;

  if( egrep( pattern:"<title>PHP Support Tickets", string:buf, icase:TRUE ) ) {

    vers = "unknown";
    version = eregmatch( string:buf, pattern:"PHP Support Tickets v([0-9.]+)", icase:TRUE );

    if( ! isnull( version[1] ) ) {
      vers = chomp( version[1] );
    }

    set_kb_item( name:"www/" + port + "/php_support_tickets", value:vers + " under " + install );
    set_kb_item( name:"php_support_tickets/installed", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:triangle_solutions:php_support_tickets:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:triangle_solutions:php_support_tickets";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"PHP Support Tickets",
                                               version:vers,
                                               install:install,
                                               cpe:cpe,
                                               concluded:version[0] ),
                                               port:port );
    exit( 0 );
  }
}

exit( 0 );
