###############################################################################
# OpenVAS Vulnerability Test
#
# osCSS Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901135");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("osCSS Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script detects the version of osCSS on remote host
  and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/catalog", "/osCSS", "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( rcvRes =~ "HTTP/1.. 200" && ">osCSS" >< rcvRes ) {

    version = "unknown";

    ver = eregmatch( pattern:'(<b>osCSS |<strong>)([0-9.]+)(.?([a-zA-Z0-9]+))?', string:rcvRes );

    if( ver[2] != NULL ) {
      if( ver[4] != NULL ) {
        version = ver[2] + "." + ver[4];
      } else {
        version = ver[2];
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/osCSS", value:tmp_version );
    set_kb_item( name:"oscss/detected", value:TRUE );

    cpe = build_cpe( value: version, exp:"^([0-9.]+)(.?([a-zA-Z0-9]+))?", base:"cpe:/a:oscss:oscss:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:oscss:oscss';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"osCSS",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
