##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mahara_detect.nasl 10059 2018-06-04 09:23:28Z asteins $
#
# Mahara Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By : Sooraj KS <kssooraj@secpod.com> on 2011-03-30
# Added /ChangeLog to detect recent version.
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900381");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10059 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-04 11:23:28 +0200 (Mon, 04 Jun 2018) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Mahara Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Mahara and
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

foreach dir( make_list_unique( "/mahara" , "/", "/mahara/htdocs", "/htdocs", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( "Welcome to Mahara" >!< rcvRes ) {
    rcvRes = http_get_cache( item: dir + "/admin/index.php", port:port );
  }

  if( rcvRes =~ "HTTP/1.. 200" && ( "Log in to Mahara" >< rcvRes || "Welcome to Mahara" >< rcvRes ) ) {

    set_kb_item( name:"mahara/detected", value:TRUE );
    version = "unknown";

    foreach file( make_list( "/Changelog", "/ChangeLog", "/debian/Changelog" ) ) {
      rcvRes2 = http_get_cache( item: dir + file, port:port );
      if( "mahara" >< rcvRes2 ) {
        # For greping the version lines
        ver = egrep( pattern:"([0-9.]+[0-9.]+[0-9]+ \([0-9]{4}-[0-9]{2}-[0-9]{2}\))", string:rcvRes2 );
        # For matching the first occurring version
        ver = eregmatch( pattern:"^(mahara\ )?\(?(([0-9.]+[0-9.]+[0-9]+)(\~" +
                                 "(beta|alpha)([0-9]))?\-?([0-9])?)\)?([^0-9]"+
                                 "|$)", string:ver );
        # For replacing '~' or '-' with '.'
        ver = ereg_replace( pattern:string("[~|-]"), replace:string("."), string:ver[2] );
      }

      if( ver != NULL ) {
        version = ver;
        break;
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/"+ port + "/Mahara", value:tmp_version );

    cpe = build_cpe( value:version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:mahara:mahara:" );
    if( isnull( cpe ) )
        cpe = 'cpe:/a:mahara:mahara';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Mahara",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
