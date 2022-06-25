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
  script_oid("1.3.6.1.4.1.25623.1.0.807073");
  script_version("2021-09-29T15:21:15+0000");
  script_tag(name:"last_modification", value:"2021-10-01 10:33:46 +0000 (Fri, 01 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-02-18 10:58:19 +0530 (Thu, 18 Feb 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sophos Unified Thread Management (UTM) Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Sophos Unified Thread Management (UTM).");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 4444);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.sophos.com/en-us/products/unified-threat-management.aspx");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 4444);

res = http_get_cache(port: port, item: "/");

if ("Sophos UTM" >< res && ('copyright">Powered by UTM Web Protection' >< res || "login to WebAdmin" >< res)) {
  version = "unknown";

  url = "/help/en_US/Content/master/Welcome_Ohelp.htm";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  # Only on WebAdmin available
  # class="sophosversionL">9.350</span>
  vers = eregmatch(pattern: '"sophosversionL">([0-9.]+)<', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  set_kb_item(name: "sophos/utm/detected", value: TRUE);
  set_kb_item(name: "sophos/utm/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:sophos:unified_threat_management:");
  if (!cpe)
    cpe = "cpe:/a:sophos:unified_threat_management";

  os_register_and_report(os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", runs_key: "linux",
                         desc: "Sophos Unified Thread Management (UTM) Detection (HTTP)");

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Sophos Unified Thread Management (UTM)", version: version,
                                           install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
