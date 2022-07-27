# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.148154");
  script_version("2022-05-24T03:45:40+0000");
  script_tag(name:"last_modification", value:"2022-05-24 03:45:40 +0000 (Tue, 24 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-20 07:40:25 +0000 (Fri, 20 May 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SurgeMail Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of SurgeMail.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/surgeweb";
res = http_get_cache(port: port, item: url);

if (("Surgeweb login page for all interfaces" >< res || "switching interface to surgeweb basic" >< res) &&
    "You are using surgeweb with an untested or unsupported browser" >< res) {
  version = "unknown";
  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "surgemail/detected", value: TRUE);
  set_kb_item(name: "surgemail/http/detected", value: TRUE);
  set_kb_item(name: "surgemail/http/port", value: port);

  url = "/help/updates.htm";
  res = http_get_cache(port: port, item: url);
  # <h3>SurgeMail 7.4b</h3>
  if (vers = eregmatch(pattern: "<h3>SurgeMail ([0-9.a-z]+)", string: res)) {
    version = vers[1];
    set_kb_item(name: "surgemail/http/" + port + "/concluded", value: vers[0]);
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  set_kb_item(name: "surgemail/http/" + port + "/concludedUrl", value: concUrl);
  set_kb_item(name: "surgemail/http/" + port + "/version", value: version);

  exit(0);
}

exit(0);
