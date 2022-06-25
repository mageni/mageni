#############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipam_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# phpIPAM Web Application Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107046");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-12 13:18:59 +0200 (Mon, 12 Sep 2016)");
  script_name("phpIPAM Web Application Detection");

  script_tag(name:"summary", value:"This script performs HTTP based detection of phpIPAM Web Application");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

http_port = get_http_port( default:80 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/phpipam", cgi_dirs( port:http_port ) ) ) {

  if( rootInstalled ) break;

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + '/?page=login';
  req = http_get( item:url, port:http_port );
  buf = http_keepalive_send_recv( port:http_port, data:req );
  if( isnull( buf ) ) continue;

  if( buf =~ "^HTTP/1\.[01] 200" && "phpIPAM IP address management" >< buf ) {

    if( dir == "" ) rootInstalled = TRUE;

    vers = 'unknown';

    #<a href="http://phpipam.net">phpIPAM IP address management [v1.3]</a>
    #</span>
    #phpIPAM IP address management [v1.1] rev010
    #<span
    version = eregmatch( pattern:'phpIPAM IP address management \\[v([0-9.]+)\\]( rev([0-9]+))?', string:buf );

    if( version[1] && version[3] ) {
      vers = version[1] + "." + version[3];
    } else if( version[1] ) {
      vers = version[1];
    }

    set_kb_item( name:"phpipam/" + http_port + "/version", value:vers );
    set_kb_item( name:"phpipam/installed", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:phpipam:phpipam:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:phpipam:phpipam";

    register_product( cpe:cpe, location:install, port:http_port, service:'www' );
    log_message( data:build_detection_report( app:'phpIPAM',
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:http_port );
  }
}

exit( 0 );
