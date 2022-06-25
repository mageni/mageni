# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:xwiki:xwiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144569");
  script_version("2020-09-14T06:17:58+0000");
  script_tag(name:"last_modification", value:"2020-09-14 09:56:38 +0000 (Mon, 14 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-14 05:57:30 +0000 (Mon, 14 Sep 2020)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2020-15171");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki < 11.10.5, 12.x < 12.2.1 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"XWiki is prone to a remote code execution vulnerability.");

  script_tag(name:"insight", value:"Any user with SCRIPT right (EDIT right before XWiki 7.4) can gain access to
  the application server Servlet context which contains tools allowing to instantiate arbitrary Java objects and
  invoke methods that may lead to arbitrary code execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"XWiki prior to version 11.10.5 or 12.2.1.");

  script_tag(name:"solution", value:"Update to version 11.10.5, 12.2.1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-7qw5-pqhc-xm4g");

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

if (version_is_less(version: version, test_version: "11.10.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.10.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
