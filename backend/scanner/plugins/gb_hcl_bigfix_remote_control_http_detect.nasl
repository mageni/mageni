# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106414");
  script_version("2022-05-09T06:06:23+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"creation_date", value:"2016-11-28 11:22:24 +0700 (Mon, 28 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HCL / IBM BigFix Remote Control Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of HCL / IBM BigFix Remote Control.");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

req = http_get(port: port, item: "/trc/");
res = http_keepalive_send_recv(port: port, data: req);

if ((res =~ "<title>(IBM )?BigFix Remote Control" ||
     res =~ "<title>(IBM|Tivoli) Endpoint Manager for Remote Control") && 'action="/trc/logon.do' >< res) {
  version = "unknown";

  vers = eregmatch(pattern: 's_about_version="([0-9.]+)', string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "hcl/bigfix/remote_control/detected", value: TRUE);
  set_kb_item(name: "hcl/bigfix/remote_control/http/detected", value: TRUE);

  cpe1 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:hcltech:bigfix_remote_control:");
  cpe2 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:bigfix_remote_control:");
  if (!cpe1) {
    cpe1 = "cpe:/a:hcltech:bigfix_remote_control";
    cpe2 = "cpe:/a:ibm:bigfix_remote_control";
  }

  register_product(cpe: cpe1, location: "/trc", port: port, service: "www");
  register_product(cpe: cpe2, location: "/trc", port: port, service: "www");

  log_message(data: build_detection_report(app: "HCL BigFix Remote Control", version: version,
                                           install: "/trc", cpe: cpe1, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
