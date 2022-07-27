###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_exponet_cms_detect.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# Exponent CMS Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100937");
  script_version("$Revision: 10894 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-12-09 13:44:03 +0100 (Thu, 09 Dec 2010)");
  script_name("Exponent CMS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exponentcms.org");

  script_tag(name:"summary", value:"Detection of Exponent CMS.

  This script sends a connection request to the server and attempts
  to detect the presence of Exponent CMS and to extract its version");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/exponent", "/cms", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach page( make_list( "/index.php", "/login.php", "/index.php?controller=login&action=showlogin" ) ) {

    url = dir + page;
    buf = http_get_cache( item:url, port:port );
    if( buf == NULL ) continue;

    if( egrep( pattern:'meta name="Generator" content="Exponent', string:buf, icase:TRUE ) ||
        ( ">Exponent CMS" ><  buf && "EXPONENT.LANG" >< buf ) ) {

      vers = "unknown";

      version = eregmatch( string:buf, pattern:'Exponent Content Management System - ([^"]+)', icase:TRUE );
      if( version[1] ) {
        version2 = eregmatch( string:version[1], pattern:'v([0-9.]+)' );
        if( version2 ) {
          vers = version2[1];
        } else {
          version2 = eregmatch( string:version[1], pattern:'([0-9.]+)' );
          if( version2 ) vers = version2[1];
        }
        patch = eregmatch( string: version[0], pattern:'patch([0-9]+)');
        if( patch[1] && vers != "unknown" ){
          vers += "." + patch[1];
        }
      }

      set_kb_item( name:"ExponentCMS/installed", value:TRUE );
      set_kb_item( name:"www/" + port + "/exponent", value:vers + " under " + install );

      cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:exponentcms:exponent_cms:" );
      if( isnull( cpe ) )
        cpe = "cpe:/a:exponentcms:exponent_cms";

      register_product( cpe:cpe, location:install, port:port );

      log_message( data:build_detection_report( app:"Exponent Content Management System",
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
