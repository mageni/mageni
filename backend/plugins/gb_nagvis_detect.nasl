###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagvis_detect.nasl 10906 2018-08-10 14:50:26Z cfischer $
#
# NagVis Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106637");
  script_version("$Revision: 10906 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:50:26 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-03-08 12:16:59 +0700 (Wed, 08 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NagVis Detection");

  script_tag(name:"summary", value:"Detection of NagVis

The script sends a HTTP connection request to the server and attempts to detect the presence of NagVis and to
extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.nagvis.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

foreach dir (make_list_unique("/nagvis", cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  req = http_get(port: port, item: dir + "/frontend/nagvis-js/index.php");
  res = http_keepalive_send_recv(port: port, data: req);

  if ("\/nagvis\/userfiles\/sounds\/" >< res && "Log In</title>" >< res) {
    version = "unknown";

    vers = eregmatch(pattern: 'title="NagVis ([0-9b.]+)', string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "nagvis/version", value: version);
    }

    set_kb_item(name: "nagvis/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9b.]+)", base: "cpe:/a:nagvis:nagvis:");
    if (!cpe)
      cpe = 'cpe:/a:nagvis:nagvis';

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "NagVis", version: version, install: install, cpe: cpe,
                                             concluded: vers[0]),
                port: port);
    exit(0);
  }
}

exit(0);
