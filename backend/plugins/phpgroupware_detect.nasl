###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpgroupware_detect.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# phpgroupware Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100092");
  script_version("$Revision: 10908 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-03-30 14:26:52 +0200 (Mon, 30 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("phpGroupWare Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://phpgroupware.org/");

  script_tag(name:"summary", value:"This host is running phpGroupWare, a web based messaging,
  collaboration and enterprise management platform.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/phpgroupware", "/phpgw", cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item: dir + "/login.php", port:port );
  if( buf == NULL ) continue;

  if( egrep( pattern:'<meta name="AUTHOR" content="phpGroupWare http://www.phpgroupware.org" />', string:buf ) ||
      egrep( pattern:'powered by phpGroupWare', string:buf ) ||
      egrep( pattern:'http://www.phpgroupware.org"><img src=.*logo.gif" alt="phpGroupWare"', string:buf ) ||
      ( egrep( pattern:">phpGroupWare [0-9.]<", string:buf ) && egrep( pattern:'type="hidden" name="passwd_type"', string:buf ) ) ) {

    if( dir == "" ) rootInstalled = TRUE;
    vers = "unknown";
    version = eregmatch( string:buf, pattern:'<font color="#000000" size="-1">phpGroupWare ([0-9.]+)</font>' );

    if( ! isnull( version[1] ) ) {
      vers = version[1];
    } else {
      version = eregmatch( string:buf, pattern:'<font color="000000" size="-1">([0-9.]+)</font>' );
      if( ! isnull( version[1] ) ) {
        vers = version[1];
      }
    }

    tmp_version = vers + " under " + install;
    set_kb_item( name:"www/" + port + "/phpGroupWare", value:tmp_version );
    set_kb_item( name:"phpGroupWare/installed", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:phpgroupware:phpgroupware:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:phpgroupware:phpgroupware';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"phpGroupWare",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
  }
}

exit( 0 );
