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

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117525");
  script_version("2021-07-01T13:08:24+0000");
  script_tag(name:"last_modification", value:"2021-07-02 10:34:13 +0000 (Fri, 02 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-01 12:57:38 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-21704", "CVE-2021-21705");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 7.3.29 Multiple Vulnerabilities (Jul 2021) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2021-21705: SSRF bypass in FILTER_VALIDATE_URL.

  - CVE-2021-21704: Stack buffer overflow in firebird_info_cb.

  - CVE-2021-21704: SIGSEGV in firebird_handle_doer.

  - CVE-2021-21704: SIGSEGV in firebird_stmt_execute.

  - CVE-2021-21704: Crash while parsing blob data in firebird_fetch_blob.");

  script_tag(name:"affected", value:"PHP versions prior to 7.3.29.");

  script_tag(name:"solution", value:"Update to version 7.3.29 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.3.29");
  script_xref(name:"URL", value:"http://bugs.php.net/81122");
  script_xref(name:"URL", value:"http://bugs.php.net/76448");
  script_xref(name:"URL", value:"http://bugs.php.net/76449");
  script_xref(name:"URL", value:"http://bugs.php.net/76450");
  script_xref(name:"URL", value:"http://bugs.php.net/76452");

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

if (version_is_less(version: version, test_version: "7.3.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);