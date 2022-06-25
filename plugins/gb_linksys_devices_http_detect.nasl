# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812041");
  script_version("2020-09-08T05:02:02+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-09-09 09:59:16 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"creation_date", value:"2017-10-19 12:33:14 +0530 (Thu, 19 Oct 2017)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Linksys Device Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP detection of Linksys devices.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ('WWW-Authenticate: Basic realm="Linksys' >!< res && "Vendor:LINKSYS" >!< res && "title>Linksys" >!< res)
  exit(0);

model = "unknown";
version = "unknown";

set_kb_item(name: "linksys/detected", value: TRUE);
set_kb_item(name: "linksys/http/port", value: port);

mod = eregmatch(pattern: 'Basic realm="Linksys[- ]([^"]+)', string: res);
if (!isnull(mod[1])) {
  model = mod[1];
  concluded = '\n    Model:        ' + mod[0];
} else {
  # Linksys Smart Wi-Fi uses JNAP
  url = "/JNAP/";
  headers = make_array("X-JNAP-Action", "http://cisco.com/jnap/core/GetDeviceInfo");
  data = "{
          }";

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res2 = http_keepalive_send_recv(port: port, data: req);

  # "modelNumber": "EA4500",
  # "firmwareVersion": "2.1.42.183584",
  mod = eregmatch(pattern: '"modelNumber": "([^"]+)', string: res2);
  if (!isnull(mod[1])) {
    model = mod[1];
    concluded = '\n    Model:        ' + mod[0];
    set_kb_item(name: "linksys/http/" + port + "/concludedUrl",
                value: http_report_vuln_url(port: port, url: url, url_only: TRUE));

    vers = eregmatch(pattern: '"firmwareVersion": "([0-9.]+)"', string: res2);
    if (!isnull(vers[1])) {
      version = vers[1];
      concluded += '\n    Version:      ' + vers[0];
    }
  } else {
    # ModelName:WVBR0-25-US
    # Firmware Version: 1.0.42.185838
    mod = eregmatch(pattern: 'ModelName:([A-Z0-9-]+)-[^\r\n]+', string: res);
    if (!isnull(mod[1])) {
      model = mod[1];
      concluded = '\n    Model:        ' + mod[0];
    }

    vers = eregmatch(pattern: 'Firmware Version: ([0-9.]+)', string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concluded += '\n    Version:      ' + vers[0];
    }
  }
}

set_kb_item(name: "linksys/http/" + port + "/model", value: model);
set_kb_item(name: "linksys/http/" + port + "/version", value: version);

if (concluded)
  set_kb_item(name: "linksys/http/" + port + "/concluded", value: concluded);

exit(0);
