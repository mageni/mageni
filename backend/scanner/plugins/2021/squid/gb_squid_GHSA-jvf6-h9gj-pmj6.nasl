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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145600");
  script_version("2021-03-22T05:19:07+0000");
  script_tag(name:"last_modification", value:"2021-03-22 05:19:07 +0000 (Mon, 22 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-22 05:11:48 +0000 (Mon, 22 Mar 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-25097");

  script_name("Squid 2.0 < 4.14, 5.0.1 < 5.0.5 HTTP Request Smuggling Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_squid_detect.nasl");
  script_mandatory_keys("squid_proxy_server/installed");

  script_tag(name:"summary", value:"Squid is prone to an HTTP request smuggling vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to improper input validation, it allows a trusted client to perform
  HTTP Request Smuggling and access services otherwise forbidden by the security controls. This occurs for
  certain uri_whitespace configuration settings.");

  script_tag(name:"affected", value:"Squid version 2.0 through 4.13 and 5.0.1 through 5.0.4.");

  script_tag(name:"solution", value:"Update to version 4.13, 5.0.5 or later. See the referenced vendor
  advisory for a workaround.");

  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-jvf6-h9gj-pmj6");

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

if (version_in_range(version: version, test_version: "2.0", test_version2: "4.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.1", test_version2: "5.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
