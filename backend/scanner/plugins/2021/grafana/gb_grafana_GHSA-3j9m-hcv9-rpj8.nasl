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

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147109");
  script_version("2021-11-08T14:03:29+0000");
  script_tag(name:"last_modification", value:"2021-11-08 14:03:29 +0000 (Mon, 08 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-05 06:04:30 +0000 (Fri, 05 Nov 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-05 16:11:00 +0000 (Fri, 05 Nov 2021)");

  script_cve_id("CVE-2021-41174");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana XSS Vulnerability (GHSA-3j9m-hcv9-rpj8)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In affected versions if an attacker is able to convince a
  victim to visit a URL referencing a vulnerable page, arbitrary JavaScript content may be executed
  within the context of the victim's browser. The user visiting the malicious link must be
  unauthenticated and the link must be for a page that contains the login button in the menu bar.
  The url has to be crafted to exploit AngularJS rendering and contain the interpolation binding
  for AngularJS expressions. AngularJS uses double curly braces for interpolation binding: {{ }}.
  When the user follows the link and the page renders, the login button will contain the original
  link with a query parameter to force a redirect to the login page. The URL is not validated and
  the AngularJS rendering engine will execute the JavaScript expression contained in the URL.");

  script_tag(name:"affected", value:"Grafana version 8.0.0-beta1 through 8.2.2.");

  script_tag(name:"solution", value:"Update to version 8.2.3 or later.");

  script_xref(name:"URL", value:"https://github.com/grafana/grafana/security/advisories/GHSA-3j9m-hcv9-rpj8");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
