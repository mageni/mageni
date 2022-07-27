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

CPE = "cpe:/a:givewp:give";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147731");
  script_version("2022-03-01T08:05:07+0000");
  script_tag(name:"last_modification", value:"2022-03-01 11:00:30 +0000 (Tue, 01 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-01 07:44:07 +0000 (Tue, 01 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2021-25099", "CVE-2021-25100", "CVE-2022-0252");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress GiveWP Plugin < 2.17.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/give/detected");

  script_tag(name:"summary", value:"The WordPress plugin GiveWP is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-25099: Unauthenticated reflected cross-site scripting (XSS)

  - CVE-2021-25100: Reflected cross-site scripting (XSS) via Import Tool

  - CVE-2022-0252: Reflected cross-site scripting (XSS) via Donation Forms Dashboard");

  script_tag(name:"affected", value:"WordPress GiveWP plugin prior to version 2.17.3.");

  script_tag(name:"solution", value:"Update to version 2.17.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/87a64b27-23a3-40f5-a3d8-0650975fee6f");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/b0e551af-087b-43e7-bdb7-11d7f639028a");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/fe2c02bf-207c-43da-98bd-4c85d235de8b");

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

if (version_is_less(version: version, test_version: "2.17.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.17.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
