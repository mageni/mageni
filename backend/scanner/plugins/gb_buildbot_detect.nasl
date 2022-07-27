###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_buildbot_detect.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# Buildbot Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800933");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10894 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Buildbot Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8010);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Buildbot
  and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8010 );

foreach dir( make_list_unique( "/", "/buildbot", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  sndReq = http_get( item:dir + "/about", port:port );
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if( rcvRes =~ "HTTP/1.. 200" && "Buildbot" >< rcvRes ) {

    version = "unknown";

    ver = eregmatch( pattern:"Buildbot.?.?(([0-9.]+)([a-z][0-9]+)?)", string:rcvRes );

    if( ! isnull( ver[2] ) ) {
      if( ! isnull( ver[3] ) ) {
        version = ver[2] + "." + ver[3];
      } else {
        version = ver[2];
      }
    }

    set_kb_item( name:"Buildbot/Ver", value:version );

    cpe = build_cpe( value: version, exp:"^([0-9.]+\.[0-9])([a-z][0-9]+)?", base:"cpe:/a:buildbot:buildbot:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:buildbot:buildbot';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Build bot",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );