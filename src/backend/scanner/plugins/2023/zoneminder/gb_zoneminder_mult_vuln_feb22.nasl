# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:zoneminder:zoneminder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126367");
  script_version("2023-02-28T10:08:51+0000");
  script_tag(name:"last_modification", value:"2023-02-28 10:08:51 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-27 11:27:46 +0000 (Mon, 27 Feb 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");

  script_cve_id("CVE-2023-25825", "CVE-2023-26032", "CVE-2023-26034", "CVE-2023-26035",
                "CVE-2023-26036", "CVE-2023-26037", "CVE-2023-26038", "CVE-2023-26039");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZoneMinder < 1.36.33, 1.37.x < 1.37.33 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_detect.nasl");
  script_mandatory_keys("zoneminder/installed");

  script_tag(name:"summary", value:"ZoneMinder is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-25825: XSS/JS-RCE in log viewing

  - CVE-2023-26032: SQL injection via malicious jwt token

  - CVE-2023-26034: SQL injection at the /zm/index.php endpoint

  - CVE-2023-26035: Unauthenticated RCE in snapshots

  - CVE-2023-26036: Local file inclusion in '/web/index.php'

  - CVE-2023-26037: SQL injection in report_event_audit

  - CVE-2023-26038: Local file inclusion in 'web/ajax/modal.php'

  - CVE-2023-26039: Command injection in daemonControl() API");

  script_tag(name:"affected", value:"ZoneMinder prior to version 1.36.33 and version 1.37.x prior
  to 1.37.33.");

  script_tag(name:"solution", value:"Update to version 1.36.33, 1.37.33 or later.");

  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-68vf-g4qm-jr6v");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-6c72-q9mw-mwx9");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-222j-wh8m-xjrx");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-72rg-h4vf-29gr");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-h5m9-6jjc-cgmw");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-65jp-2hj3-3733");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-wrx3-r8c4-r24w");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-44q8-h2pw-cc9g");

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

if (version_is_less(version: version, test_version: "1.36.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.36.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.37.0", test_version_up: "1.37.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.37.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
