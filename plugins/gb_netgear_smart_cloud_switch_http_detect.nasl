# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.146185");
  script_version("2021-06-29T07:38:55+0000");
  script_tag(name:"last_modification", value:"2021-07-01 10:12:29 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-06-29 04:32:16 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NETGEAR Smart Cloud Switch Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of NETGEAR Smart Cloud Switches.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.netgear.com/business/wired/switches/smart-cloud/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ("login.html?aj4=" >!< res)
  exit(0);

url = "/cgi/get.cgi?cmd=home_login&dummy=1624942615990&bj4=d201208b4705815b2342087be4ba43c1";

headers = make_array("X-Requested-With", "XMLHttpRequest");

req = http_get_req(port: port, url: url, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if ('"modelName"' >< res && "NETGEAR" >< res) {
  version = "unknown";
  model = "Unknown Model";
  install = "/";

  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  # "model": "GS752TPv2",
  mod = eregmatch(pattern: '"model":[^"]+"([^"]+)"', string: res);
  if (!isnull(mod[1]))
    model = mod[1];

  # "fwVer":  "V6.0.4.8",
  vers = eregmatch(pattern: '"fwVer":[^"]+"V([^"]+)"', string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  os_name = "NETGEAR " + model + " Firmware";
  hw_name = "NETGEAR " + model;

  if (model != "Unknown Model") {
    os_cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                       base: "cpe:/o:netgear:" + tolower(model) + "_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:netgear:" + tolower(model) + "_firmware";

    hw_cpe = "cpe:/h:netgear:" + tolower(model);
  } else {

    os_cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:netgear:smart_cloud_switch_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:netgear:smart_cloud_switch_firmware";

    hw_cpe = "cpe:/h:netgear:smart_cloud_switch";
  }

  # "mac":  "28:80:88:6F:D2:68"
  mac = eregmatch(pattern: '"mac":[^"]+"([^"]+)', string: res);
  if (!isnull(mac[1])) {
    register_host_detail(name: "MAC", value: mac[1], desc: "NETGEAR Smart Cloud Switch Detection (HTTP)");
    replace_kb_item(name: "Host/mac_address", value: mac[1]);
  }

  set_kb_item(name: "netgear/smart_cloud_switch/detected", value: TRUE);
  set_kb_item(name: "netgear/smart_cloud_switch/http/detected", value: TRUE);

  os_register_and_report(os: os_name, cpe: os_cpe, desc: "NETGEAR Smart Cloud Switch Detection (HTTP)",
                         runs_key: "unixoide");

  register_product(cpe: os_cpe, location: install, port: port, service: "www");
  register_product(cpe: hw_cpe, location: install, port: port, service: "www");

  report = build_detection_report(app: os_name, version: version, install: install,
                                  cpe: os_cpe, concluded: vers[0], concludedUrl: concUrl);

  report += '\n\n' + build_detection_report(app: hw_name, install: install, cpe: hw_cpe,
                                            skip_version: TRUE);

  log_message(data: report, port: port);
}

exit(0);
