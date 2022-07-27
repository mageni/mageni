###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sysaid_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# SysAid Help Desk Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106004");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-11 10:02:43 +0700 (Thu, 11 Jun 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("SysAid Help Desk Detection");

  script_tag(name:"summary", value:"Detection of SysAid Help Desk Software

The script sends a connection request to the server and attempts to detect SysAid Help Desk Software.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

include("cpe.inc");
include("host_details.inc");

port = get_http_port(default: 8080);

foreach dir( make_list_unique( "/sysaid", cgi_dirs( port:port ) ) ) {

  rep_dir = dir;
  if (dir == "/") dir = "";

  url = dir + '/Login.jsp';
  buf = http_get_cache(item: url, port: port);

  if (buf =~ "HTTP/1\.. 200" && (buf =~ "SysAid Help Desk Software" ||
                                 buf =~ "Software del Servicio de asistencia de SysAid")) {
    vers = string("unknown");
    url = dir + '/errorInSignUp.htm';
    req = http_get(item: url, port: port);
    buf = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);
    version = eregmatch(string: buf, pattern: "css/master.css\?v([0-9.]+)", icase: TRUE);
    if (!isnull(version[1]))
      vers = chomp(version[1]);

    set_kb_item(name: string("www/", port, "/sysaid"), value: vers);
    set_kb_item(name: "sysaid/installed", value: TRUE);

    cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:sysaid:sysaid:");
    if (isnull(cpe))
      cpe = 'cpe:/a:sysaid:sysaid';

    register_product(cpe: cpe, location:rep_dir, port: port);

    log_message(data: build_detection_report(app: "SysAid Help Desktop Software", version: vers,
                                             install: rep_dir, cpe: cpe, concluded: version[0]),
                port: port);
  }
}

exit(0);
