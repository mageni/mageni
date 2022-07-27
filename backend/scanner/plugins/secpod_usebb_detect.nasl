##############################################################################
# OpenVAS Vulnerability Test
#
# UseBB Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.901056");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("UseBB Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed UseBB version and sets
  the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/UseBB", "/usebb", "/forum", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( rcvRes =~ "HTTP/1.. 200" && ( '<a href="http://www.usebb.net">UseBB 1 Forum Software</a>' >< rcvRes ||
      'content="forum,board,community,usebb"' >< rcvRes ) ) {

    version = "unknown";

    sndReq = http_get( item: dir + "/Changelog.txt", port:port );
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    ver = eregmatch( pattern:"UseBB (([0-9.]+)( ?(beta|RC|a|b)( ?[0-9]+)?)?)", string:rcvRes );
    ver[1] = ereg_replace( pattern:" ", string:ver[1], replace: "." );
    if( ver[1] != NULL ) version = ver[1];

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/"+ port + "/UseBB", value:tmp_version );
    set_kb_item( name:"usebb/detected", value:TRUE );

    cpe = build_cpe( value: version, exp:"^([0-9.]+)\.([0-9a-zA-Z.]+)", base:"cpe:/a:usebb:usebb:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:usebb:usebb';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"UseBB",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
