# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.811015");
  script_version("2023-03-09T10:09:20+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:20 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"creation_date", value:"2017-04-27 10:34:57 +0530 (Thu, 27 Apr 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Oracle E-Business Suite (EBS) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Oracle E-Business Suite (EBS).");

  script_xref(name:"URL", value:"https://www.oracle.com/applications/ebusiness/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default: 443);

url = "/OA_HTML/AppsLocalLogin.jsp";

# Response might include a dynamic redirect URL so we don't use http_get_cache()
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if ('title="Oracle Logo"' >!< res || "message=FND_SSO_USER_NAME>User Name" >!< res) {
  if (res =~ "^HTTP/1\.[01] 30[0-9]") {
    loc = http_extract_location_from_redirect(port: port, data: res, current_dir: "/");
    if (!loc || loc !~ "^/OA_HTML/RF\.jsp")
      exit(0);

    url = loc;
    # Response might include a dynamic redirect URL so we don't use http_get_cache()
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);
    if ("<title>Login</title>" >!< res || 'content="Oracle UIX"' >!< res) {
      exit(0);
    }
  } else {
    exit(0);
  }
}

version = "unknown";
install = "/";

set_kb_item(name: "oracle/ebs/detected", value: TRUE);
set_kb_item(name: "oracle/ebs/http/detected", value: TRUE);

conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

url = "/OA_HTML/FrmReportData";
res = http_get_cache(port: port, item: url);

# /OA_HTML/cabo/jsLibs/Common12_2_11_0_0.js
vers = eregmatch(pattern: '/OA_HTML/cabo/jsLibs/Common([0-9]+_[0-9]+_[0-9]+)[^"]+', string: res);
if (!isnull(vers[1])) {
  version = str_replace(string: vers[1], find: "_", replace: ".");
  conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:oracle:e-business_suite:");
if (!cpe)
  cpe = "cpe:/a:oracle:e-business_suite";

register_product(cpe: cpe, location: install, port: port, service: "www");

log_message(data: build_detection_report(app: "Oracle E-Business Suite (EBS)", version: version,
                                         install: install, cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
            port: port);

exit(0);
