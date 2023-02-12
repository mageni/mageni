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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105753");
  script_version("2023-02-09T10:17:23+0000");
  script_tag(name:"last_modification", value:"2023-02-09 10:17:23 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"creation_date", value:"2016-06-10 12:33:05 +0200 (Fri, 10 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("VMware vRealize Log Insight Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of VMware vRealize Log Insight.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/login";

res = http_get_cache(port: port, item: url);

if ("<title>vRealize Log Insight - Login</title>" >!< res)
  exit(0);

version = "unknown";
build = "unknown";
concUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "vmware/vrealize_log_insight/detected", value: TRUE);
set_kb_item(name: "vmware/vrealize_log_insight/http/detected", value: TRUE);
set_kb_item(name: "vmware/vrealize_log_insight/http/port", value: port);

# Note: Newer versions (at least 8.x) need authentication
url = "/api/v1/version";
res = http_get_cache(port: port, item: url);

# {"releaseName":"GA","version":"4.0.0-4624504"}
if ('"releaseName"' >< res) {
  vers = eregmatch(pattern: '"version":"([0-9.]+)-([0-9]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    set_kb_item(name: "vmware/vrealize_log_insight/http/" + port + "/concluded", value: vers[0]);
  }

  if (!isnull(vers[2]))
    build = vers[2];
}

set_kb_item(name: "vmware/vrealize_log_insight/http/" + port + "/version", value: version);
set_kb_item(name: "vmware/vrealize_log_insight/http/" + port + "/build", value: build);
set_kb_item(name: "vmware/vrealize_log_insight/http/" + port + "/concludedUrl", value: concUrl);

exit(0);
