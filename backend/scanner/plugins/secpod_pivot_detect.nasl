###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pivot_detect.nasl 8992 2018-03-01 09:17:20Z cfischer $
#
# Pivot Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900578");
  script_version("$Revision: 8992 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-01 10:17:20 +0100 (Thu, 01 Mar 2018) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Pivot Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.pivotlog.net");

  script_tag(name:"summary", value:"This script detects the installed version of Pivot and
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

foreach dir( make_list_unique( "/pivot", "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/pivot/index.php", port:port );

  # nb: Don't use only '<title>Pivot' to avoid false positives against Pivot3 which is a completely different product.
  # The login title was tested against the range of versions in the comment below so this is save to use.
  if( res =~ "^HTTP/1\.[01] 200" && ( "<title>Pivot &#187; Login</title>" >< res || '<a href="http://www.pivotlog.net' >< res ) ) {

    version     = "unknown";
    cpe_version = "unknown";

    # title="Pivot - 1.40.8: 'Dreadwind'"
    # title="Pivot - 1.30 beta 3: 'Rippersnapper'"
    # title="Pivot - 1.30 beta 1a: 'Rippersnapper'"
    # title="Pivot - 1.0: 'Grimlock'"
    vers = eregmatch( pattern:'title="Pivot - ([^:]+)', string:res );
    if( vers[1] ) {
      version     = vers[1];
      cpe_version = ereg_replace( pattern:"(alpha|beta|RC) ", replace:"\1.", string:vers[1] );
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/Pivot", value:tmp_version );
    set_kb_item( name:"Pivot/detected", value:TRUE );

    cpe = build_cpe( value:cpe_version, exp:"^([0-9.]+) ?((alpha|beta|RC)( |\.)?([0-9a-z.]+)?)?", base:"cpe:/a:pivot:pivot:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:pivot:pivot";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Pivot",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0] ),
                                              port:port );
  }
}

exit( 0 );