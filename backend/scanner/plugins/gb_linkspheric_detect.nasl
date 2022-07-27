###############################################################################
# OpenVAS Vulnerability Test
#
# linkSpheric Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.801112");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("linkSpheric Version Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of linkSpheric and
  sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/linkSpheric", "/Spheric", "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/admin/index.php", port:port );
  rcvRes2 = http_get_cache( item: dir + "/index.php", port:port );

  if( ( rcvRes =~ "HTTP/1.. 200" && ( 'generator" content="linkSpheric' >< rcvRes || ( "Powered by" >< rcvRes && "S</span>pheric" >< rcvRes ) ) ) ||
      ( rcvRes2 =~ "HTTP/1.. 200" && ( 'generator" content="linkSpheric' >< rcvRes2 || ( "Powered by" >< rcvRes2 && "S</span>pheric" >< rcvRes2 ) ) ) ) {

    version = eregmatch( pattern:"linkSpheric version ([0-9.]+( Beta [0-9.])?)", string:rcvRes, icase:1 );
    if( isnull( version ) ) {

      sndReq = http_get( item:dir + "/CHANGELOG", port:port );
      rcvRes = http_keepalive_send_recv( port:port, data:sndReq );
      version = egrep( pattern:"version [0-9.]+[a-z0-9 ]+(release)", string:rcvRes, icase:1 );
      version = eregmatch( pattern:"version ([0-9.]+( Beta [0-9])?)", string:version, icase:1 );
    }
    spheric_ver = ereg_replace( pattern:" ", replace:".", string:version[1] );

    if( ! isnull( spheric_ver ) ) {
      version = spheric_ver;
    } else {
      version = "unknown";
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/linkSpheric", value:tmp_version );
    set_kb_item( name:"linkspheric/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)\.([0-9a-zA-Z.]+)", base:"cpe:/a:dataspheric:linkspheric:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:dataspheric:linkspheric';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"linkSpheric",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:spheric_ver ),
                                              port:port );
  }
}

exit( 0 );
