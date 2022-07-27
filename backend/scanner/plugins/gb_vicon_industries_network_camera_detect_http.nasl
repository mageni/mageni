###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vicon_industries_network_camera_detect_http.nasl 10627 2018-07-25 15:49:36Z mmartin $
#
# Vicon Industries Network Camera  Detection (HTTP)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107332");
  script_version("$Revision: 10627 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:49:36 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-24 13:53:24 +0200 (Tue, 24 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Vicon Industries Network Camera Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Vicon Industries Network Cameras.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach url( make_list( "/", "/appletvid.html", "/imageset.html", "/basicset.html", "/accessset.html" ) ) {

  res = http_get_cache( item:url, port:port );
  if( !( res =~ 'Server: IQinVision Embedded' ) && !( ( res =~ '<(TITLE|title)>IQ' ) && ( res =~ '<meta name="author" content="[^>]*IQinVision">' || res =~ '<font color="#[0-9]*">IQ.*</font>' ) ) ) continue;

  set_kb_item( name:"vicon_industries/network_camera/detected", value:TRUE );
  set_kb_item( name:"vicon_industries/network_camera/http/detected", value:TRUE );
  set_kb_item( name:"vicon_industries/network_camera/http/port", value:port );

  version = "unknown";
  type    = "unknown";

  vers = eregmatch( pattern:"(V|B|Version )(V[0-9.]+)", string:res, icase:FALSE );
    if( vers[2] ) version = vers[2];

  typerecv = eregmatch( pattern:'IQ(eye)?([0578ADMPR])[^\r\n]*', string:res, icase:FALSE );

  type_list['0'] = "3 Series / 4 Series";
  type_list['5'] = "5 Series";
  type_list['7'] = "7 Series";
  type_list['8'] = "Sentinel Series";
  type_list['9'] = "9 Series";
  type_list['A'] = "Alliance-pro";
  type_list['D'] = "Alliance-mini";
  type_list['M'] = "Alliance-mx";
  type_list['P'] = "PTZ";
  type_list['R'] = "R5 Series";

  if( type_list[typerecv[2]] ) {
    type = type_list[typerecv[2]];
  } else {
    type = "unknown";
  }
  set_kb_item( name:"vicon_industries/network_camera/http/" + port + "/type", value:type );
  set_kb_item( name:"vicon_industries/network_camera/http/" + port + "/version", value:version );
  if( type != "unknown" )
    set_kb_item( name:"vicon_industries/network_camera/http/" + port + "/concluded", value:typerecv[0]);
  exit( 0 );
}
exit( 0 );
