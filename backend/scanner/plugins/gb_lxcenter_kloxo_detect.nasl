###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lxcenter_kloxo_detect.nasl 11244 2018-09-05 12:23:51Z cfischer $
#
# LxCenter Kloxo Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.103977");
  script_version("$Revision: 11244 $");
  script_name("LxCenter Kloxo Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-05 14:23:51 +0200 (Wed, 05 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-02-22 22:54:04 +0700 (Sat, 22 Feb 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("httpver.nasl");
  script_require_ports("Services/www", 7778);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://github.com/lxcenter/kloxo");

  script_tag(name:"summary", value:"This host is running LxCenter Kloxo. Kloxo is a fully scriptable
  hosting platform.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:7778 );
buf = http_get_cache( item:"/login/", port:port );
if( ! buf ) exit( 0 );

if( buf =~ "^HTTP/1\.[01] 200" && egrep( pattern:'Kloxo', string:buf, icase:TRUE ) ) {

  install = "/";
  version = "unknown";

  vers = eregmatch( string:buf, pattern:">Kloxo.* ([0-9.]+[a-z]-[0-9]+)<", icase:TRUE );
  if( ! isnull( vers[1] ) ) version = chomp( vers[1] );

  set_kb_item( name:"Kloxo/installed", value:TRUE );
  set_kb_item( name:"www/" + port + "/kloxo", value:version );

  cpe = build_cpe( value:version, exp:"^([0-9.]+[a-z]-[0-9]+)", base:"cpe:/a:lxcenter:kloxo:");
  if( isnull( cpe ) )
    cpe = "cpe:/a:lxcenter:kloxo";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"LxCenter Kloxo",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            port:port );
}

exit( 0 );