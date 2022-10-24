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

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126173");
  script_version("2022-10-21T10:20:04+0000");
  script_tag(name:"last_modification", value:"2022-10-21 10:20:04 +0000 (Fri, 21 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-18 10:30:57 +0000 (Tue, 18 Oct 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2022-3501");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Information Exposure Vulnerability (OSA-2022-14)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to a information exposure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Article template contents with sensitive data could be accessed
  from agents without permissions.");

  script_tag(name:"affected", value:"OTRS version 8.0.x through 8.0.25.");

  script_tag(name:"solution", value:"Update to version 8.0.26 or later.");

  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2022-14/");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
