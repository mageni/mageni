##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotnetnuke_detect.nasl 9608 2018-04-25 13:33:05Z jschulte $
#
# DotNetNuke Version Detection
#
# Authors:
# Antu Sanadi<santu@secpod.com>
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800683");
  script_version("$Revision: 9608 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-25 15:33:05 +0200 (Wed, 25 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DotNetNuke Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of DotNetNuke and sets the
  result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/dotnetduke", "/dnnarticle", "/cms", "/DotNetNuke", "/DotNetNuke Website", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/default.aspx", port:port );

  sndReq2 = http_get( item:dir + "/Install/InstallWizard.aspx", port:port );
  rcvRes2 = http_keepalive_send_recv( port:port, data:sndReq2 );

  sndReq3 = http_get( item:dir + "/DesktopModules/AuthenticationServices/OpenID/license.txt", port:port );
  rcvRes3 = http_keepalive_send_recv( port:port, data:sndReq3 );

  if( ( rcvRes2 =~ "HTTP/1.. 200" && "DotNetNuke Installation Wizard" >< rcvRes2 ) ||
      ( rcvRes3 =~ "HTTP/1.. 200" && "DotNetNuke" >< rcvRes3 && "www.dotnetnuke.com" >< rcvRes3 ) ||
      ( rcvRes =~ "HTTP/1.. 200" && "DotNetNuke" >< rcvRes && ( "DesktopModules" >< rcvRes ||
        "dnnVariable" >< rcvRes || "www.dotnetnuke.com" >< rcvRes || "DNN_HTML" >< rcvRes ||
        "DotNetNukeAnonymous" >< rcvRes ) ) ||

      # DotNetNuke is nowaday just called "DNN"
      # Product can be detected, but version detection would require authentication
      ( rcvRes =~ "HTTP/1.. 200" && rcvRes =~ 'id="dnn_' && rcvRes =~ 'class="DnnModule' ) ) {

    version = "unknown";

    ver = eregmatch( pattern:"DNN ([0-9.]+)", string:rcvRes );
    if( ver[1] != NULL ) version = ver[1];

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/"+ port + "/DotNetNuke", value:tmp_version );
    set_kb_item( name:"dotnetnuke/installed", value:TRUE );

    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:dotnetnuke:dotnetnuke:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:dotnetnuke:dotnetnuke';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"Dot Net Nuke",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:ver[0] ),
                                               port:port );
  }
}

exit( 0 );
