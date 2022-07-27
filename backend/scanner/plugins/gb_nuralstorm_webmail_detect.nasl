###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuralstorm_webmail_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# Nuralstorm Webmail Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100742");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10911 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-08-04 13:50:35 +0200 (Wed, 04 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Nuralstorm Webmail Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.nuralstorm.net/");

  script_tag(name:"summary", value:"This host is running Nuralstorm Webmail.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/wmail", "/webmail", "/mail", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/login.php";
  buf = http_get_cache( item:url, port:port );
  if( isnull( buf ) ) continue;

  if( egrep( pattern:"NuralStorm Webmail - Login", string:buf, icase:TRUE ) ) {

    vers = "unknown";
    set_kb_item( name:"nuralstorm_webmail/detected", value:TRUE );
    cpe = "cpe:/a:nuralstorm:nuralstorm_webmail";
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

    version = eregmatch( string:buf, pattern: "Webmail \(([^\)]+)\)",icase:TRUE );

    if( ! isnull( version[1] ) ) {
      vers = str_replace( string:version[1], find:" ", replace:"" );
      vers = chomp( vers );
      cpe += ":" + vers;
    }

    register_product( cpe:cpe, location:install, port:port, service:"www" );
    log_message( data:build_detection_report( app:"NuralStorm Webmail",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0],
                                              concludedUrl:conclUrl ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
