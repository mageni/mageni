###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ros_detect.nasl 13627 2019-02-13 10:38:43Z cfischer $
#
# Rugged Operating System Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103633");
  script_version("$Revision: 13627 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:38:43 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-01-04 12:11:14 +0100 (Fri, 04 Jan 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Detection of Rugged Operating System");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/www", 80, "Services/telnet", 23);

  script_tag(name:"summary", value:"Detection of Rugged Operating System.
  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("telnet_func.inc");
include("host_details.inc");

function check_http() {

  local_var port, version, banner, req;
  global_var concluded;

  if( http_is_cgi_scan_disabled() ) return;

  port = get_http_port(default:80);
  if( ! can_host_asp( port:port ) ) return;
  banner = get_http_banner(port:port);
  if(banner && "Server: GoAhead-Webs" >< banner) {
    url = '/InitialPage.asp';
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if("Rugged Operating System" >< buf) {
      version = eregmatch(pattern:"Rugged Operating System v([0-9.]+)", string:buf);
      if(!isnull(version[1])) {
        concluded = version[0];
        return version[1];
      }
    }
  }
}

function check_telnet() {

  local_var port, banner;
  global_var concluded;

  port = get_telnet_port(default:23);
  r = get_telnet_banner(port:port);
  if(!r || "Rugged Operating System" >!< r)
    return FALSE;

  version = eregmatch(pattern:"Rugged Operating System v([0-9.]+)", string:r);
  if(!isnull(version[1])) {
    concluded = version[0];
    return version[1];
  }
}

vers = check_http();
banner_type = "HTTP banner";

if( ! vers ) {
  vers = check_telnet();
  banner_type = "Telnet banner";
}

if(vers && !isnull(vers)) {

  cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/o:ruggedcom:ros:");
  if(isnull(cpe))
    cpe = 'cpe:/o:ruggedcom:ros';

  set_kb_item(name:"rugged_os/installed", value:TRUE);

  register_and_report_os( os:"Rugged Operating System", cpe:cpe, banner_type:banner_type, desc:"Detection of Rugged Operating System", runs_key:"unixoide" );

  log_message(data: build_detection_report(app:"Rugged Operating System", version:vers, install:"OS", cpe:cpe, concluded: concluded),port:0);
  exit(0);

}

exit(0);