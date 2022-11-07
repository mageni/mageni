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

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126185");
  script_version("2022-10-26T08:53:43+0000");
  script_tag(name:"last_modification", value:"2022-10-26 08:53:43 +0000 (Wed, 26 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-25 10:22:22 +0000 (Tue, 25 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-41741", "CVE-2022-41742");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nginx Multiple Vulnerabilities (Oct 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_mandatory_keys("nginx/detected");

  script_tag(name:"summary", value:"Nginx is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2022-41741: Attacker can cause a worker process crash or worker process memory corruption by
  using a specially crafted mp4 file.

  - CVE-2022-41742: Attacker can cause a worker process crash or worker process memory disclosure by
  using a specially crafted mp4 file.");

  script_tag(name:"affected", value:"Nginx versions 1.0.7 and later, 1.1.3 and later.

  Note: The issues only affect nginx if it is built with the ngx_http_mp4_module which is not built
  by default, and the mp4 directive is used in the configuration file.");

  script_tag(name:"solution", value:"Update to version 1.22.1, 1.23.2 or later.");

  script_xref(name:"URL", value:"https://mailman.nginx.org/archives/list/nginx-announce@nginx.org/message/RBRRON6PYBJJM2XIAPQBFBVLR4Q6IHRA/");
  script_xref(name:"URL", value:"https://nginx.org/en/security_advisories.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^1\.0\.[0-9]+" && version_is_greater_equal(version: version, test_version: "1.0.7")) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.22.1/1.23.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.1.3", test_version_up: "1.22.1")) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.22.1/1.23.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.23.0", test_version_up: "1.23.2")) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.23.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
