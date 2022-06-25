###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twiki_detect.nasl 12952 2019-01-07 06:54:36Z ckuersteiner $
#
# TWiki Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By : Rachana Shetty <srachana@secpod.com> on 2011-10-04
#  - Updated to detect latest versions by adding egrep pattern match.
#
# Updated By : Rachana Shetty <srachana@secpod.com> on 2012-03-21
#  - Updated to set KB if Twiki is installed
#
# Updated By : Shakeel <bshakeel@secpod.com> on 2015-01-06
# - Updated according to new script style
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800399");
  script_version("$Revision: 12952 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-07 07:54:36 +0100 (Mon, 07 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");

  script_name("TWiki Version Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of TWiki.

The script sends a HTTP connection request to the server and attempts to detect the presence of TWiki and
to extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

cgidirs = make_list_unique( "/", "/twiki", "/wiki", cgi_dirs( port:port ) );
subdirs = make_list( "/", "/bin", "/do", "/cgi-bin");

foreach cgidir ( cgidirs ) {
  foreach subdir( subdirs ) {
    # To avoid doubled calls and calls like //cgi-bin
    if( cgidir == "/cgi-bin" && subdir == "/cgi-bin" ) continue;
    if( cgidir != "/" && subdir == "/" ) subdir = "";
    if( cgidir == "/" ) cgidir = "";
    dirs = make_list_unique( dirs, cgidir + subdir );
  }
}

foreach dir ( dirs ) {
  install = dir;
  if( dir == "/" ) dir = "";

  sndReq = http_get( item:dir + "/view/TWiki/WebHome", port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:sndReq, bodyonly:FALSE );

  if( rcvRes =~ "HTTP/1.. 200" && ( egrep( pattern:"[p|P]owered by TWiki", string:rcvRes ) ||
                                    "This site is powered by the TWiki collaboration platform" >< rcvRes ) ) {
    # Ignore special pages like edit or rdiff
    if( "(edit)</title>" >< rcvRes || "( vs. )</title>" >< rcvRes || "This Wiki topic does not exist" >< rcvRes ||
        "/bin/view/TWiki/bin" >< dir || "/bin/rdiff/TWiki/bin" >< dir ) continue;

    version = "unknown";
    exp = "^([0-9.]+)";

    ver = eregmatch( pattern:"TWiki-([0-9.]+),", string:rcvRes );
    if( !isnull(ver[1]) ) {
      version = ver[1];
    } else {
      # nb: Old versions of Twiki before 4.0 had the release date as its version number.
      ver = eregmatch( pattern:"This site is running TWiki version <strong>([a-zA-Z0-9 ]+)</strong>",
                       string:rcvRes );
      if( !isnull(ver[1]) ) {
        version = ereg_replace( pattern:" ", string:ver[1], replace: "." );
        exp = "^([a-zA-Z0-9.]+)";
      }
    }

    set_kb_item( name:"twiki/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:exp, base:"cpe:/a:twiki:twiki:" );
    if( !cpe )
      cpe = "cpe:/a:twiki:twiki";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"TWiki", version:version, install:install, cpe:cpe,
                                               concluded:ver[0] ),
                 port: port );
  }
}

exit( 0 );
