###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wepresent_wipg_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# wePresent WiPG Device Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106781");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-21 08:12:54 +0200 (Fri, 21 Apr 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("wePresent WiPG Device Detection");

  script_tag(name:"summary", value:"Detection of wePresent WiPG devices.

The script sends a connection request to the server and attempts to detect wePresent WiPG devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.wepresentwifi.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

req = http_get(port: port, item: "/cgi-bin/web_index.cgi?lang=en&src=AwWelcome.html");
res = http_keepalive_send_recv(port: port, data: req);

if ("<title>wePresent" >< res && (("AwLoginTrainer.html" >< res && "AwLoginAdmin.html" >< res) ||
    "AwLoginBS.html" >< res)) {
  version = "unknown";
  model = '';

  cpe = 'cpe:/a:wepresent:wipg';

  mod = eregmatch(pattern: "wePresent WiPG-([0-9]+)([A-Z])?", string: res);
  if (!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name: "wepresent_wipg/model", value: model);
    cpe += '-' + model;
  }

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "wePresent WiPG " + model, version: version, install: "/",
                                           cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
