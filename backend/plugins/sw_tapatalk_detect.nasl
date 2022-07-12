###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_tapatalk_detect.nasl 12175 2018-10-31 06:20:00Z ckuersteiner $
#
# Tapatalk Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111039");
  script_version("$Revision: 12175 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-31 07:20:00 +0100 (Wed, 31 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-09-27 14:00:00 +0200 (Sun, 27 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Tapatalk Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("phpbb_detect.nasl", "gb_simple_machines_forum_detect.nasl",
  "vbulletin_detect.nasl", "secpod_woltlab_burning_board_detect.nasl",
  "sw_xenforo_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/can_host_tapatalk");

  script_xref(name:"URL", value:"https://www.tapatalk.com/");

  script_tag(name:"summary", value:"The script sends a HTTP request to
  the server and attempts to extract the version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

cpe_list = make_list( "cpe:/a:phpbb:phpbb",
                      "cpe:/a:simplemachines:smf",
                      "cpe:/a:vbulletin:vbulletin",
                      "cpe:/a:xenforo:xenforo",
                      "cpe:/a:woltlab:burning_board" );


if( ! infos = get_all_app_ports_from_list( cpe_list:cpe_list ) ) exit( 0 );
cpe  = infos['cpe'];
port = infos['port'];

if ( ! port = get_app_port( cpe:cpe ) ) exit( 0 );
if ( ! dir  = get_app_location( cpe:cpe, port:port ) ) exit( 0 );

install = dir;
if( dir == "/" ) dir = "";

url = dir + "/mobiquo/mobiquo.php";
buf = http_get_cache( item:url, port:port );

if( buf =~ "^HTTP/1\.[01] 200" && egrep( pattern:"Tapatalk", string:buf, icase:TRUE ) ) {

  version = "unknown";
  forumType = "unknown";
  cpeEdition = "";
  conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

  ver = eregmatch( pattern:"Current Tapatalk plugin version: ([0-9.]+)", string:buf );

  if( ! isnull( ver[1] ) ) version = ver[1];

  if( "?plugin=phpbb" >< buf ) {
    forumType = "phpBB";
    set_kb_item( name:"www/" + port + "/tapatalk/phpbb", value:version );
    set_kb_item( name:"tapatalk/phpbb/installed", value:TRUE );
    cpeEdition = ":::::phpbb";
  } else if( "?plugin=smf" >< buf ) {
    ver = eregmatch( pattern:"Current Tapatalk plugin version: (sm20_|sm-2a_)([0-9.]+)", string:buf );
    if( ! isnull( ver[2] ) ) version = ver[2];
    forumType = "SMF";
    set_kb_item( name:"www/" + port + "/tapatalk/smf", value:version );
    set_kb_item( name:"tapatalk/smf/installed", value:TRUE );
    cpeEdition = ":::::smf";
  } else if( "?plugin=vbulletin" >< buf ) {
    forumType = "vBulletin";
    set_kb_item( name:"www/" + port + "/tapatalk/vbulletin", value:version );
    set_kb_item( name:"tapatalk/vbulletin/installed", value:TRUE );
    cpeEdition = ":::::vbulletin";
  } else if( "?plugin=wbb" >< buf ) {
    forumType = "WBB";
    set_kb_item( name:"www/" + port + "/tapatalk/wbb", value:version );
    set_kb_item( name:"tapatalk/wbb/installed", value:TRUE );
    cpeEdition = ":::::wotlab_burning_board";
  } else if( "?plugin=xnf" >< buf ) {
    forumType = "XenForo";
    set_kb_item( name:"www/" + port + "/tapatalk/xenforo", value:version );
    set_kb_item( name:"tapatalk/xenforo/installed", value:TRUE );
    cpeEdition = ":::::xenforo";
  } else {
    set_kb_item( name:"www/" + port + "/tapatalk/unknown", value:version );
    set_kb_item( name:"tapatalk/unknown/installed", value:TRUE );
    cpeEdition = ":::::unknown";
  }

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tapatalk:tapatalk:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:tapatalk:tapatalk:" + cpeEdition;
  else
    cpe = cpe + cpeEdition;

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Tapatalk for " + forumType,
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:ver[0],
                                            concludedUrl:conclUrl ),
                                            port:port );
}

exit( 0 );
