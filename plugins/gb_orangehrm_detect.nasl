###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orangehrm_detect.nasl 11215 2018-09-04 10:11:35Z cfischer $
#
# OrangeHRM Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100850");
  script_version("$Revision: 11215 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-04 12:11:35 +0200 (Tue, 04 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-10-12 12:50:34 +0200 (Tue, 12 Oct 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OrangeHRM Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.orangehrm.com/");

  script_tag(name:"summary", value:"This host is running OrangeHRM, a Human Resource management and
  development system.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/orangehrm", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/login.php";
  buf = http_get_cache( item:url, port:port );
  if( isnull( buf ) ) continue;

  if( "<title>OrangeHRM" >< buf && "&copy; OrangeHRM Inc." >< buf && "Login Name :" >< buf )  {

    vers = "unknown";

    version = eregmatch( string:buf, pattern:"OrangeHRM</a> ver ([0-9.]+)", icase:TRUE );
    if( version[1] ) vers = chomp( version[1] );

    set_kb_item( name:"www/" + port + "/orangehrm", value:vers + " under " + install );
    set_kb_item( name:"orangehrm/detected", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:orangehrm:orangehrm:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:orangehrm:orangehrm";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"OrangeHRM",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );