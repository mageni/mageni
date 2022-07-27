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

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124052");
  script_version("2022-04-06T07:05:32+0000");
  script_tag(name:"last_modification", value:"2022-04-06 10:04:37 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-05 17:04:08 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2022-1178", "CVE-2022-1179", "CVE-2022-1180");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR <= 6.0.0.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value:"OpenEMR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-1178: Cross-site scripting (XSS)

  - CVE-2022-1179: Incorrect access control

  - CVE-2022-1180: Cross-site scripting (XSS)");

  script_tag(name:"affected", value:"OpenEMR version 6.0.0.4 and prior.");

  script_tag(name:"solution", value:"Update to version 6.0.0.4 or later.");

  script_xref(name:"URL", value:"https://github.com/openemr/openemr/commit/347ad614507183035d188ba14427bc162419778c");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/5813bd1f-b3aa-44f3-a5c0-aeeee2bf6fa4");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/0e281ea2-70f7-4ed7-8814-74502eff9dd5");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/8025e31f-7dcf-4db9-ab07-06c1e055ab42");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "6.0.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
