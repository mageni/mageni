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
  script_oid("1.3.6.1.4.1.25623.1.0.126174");
  script_version("2022-10-21T10:20:04+0000");
  script_tag(name:"last_modification", value:"2022-10-21 10:20:04 +0000 (Fri, 21 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-18 13:25:57 +0000 (Tue, 18 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-22 13:41:00 +0000 (Wed, 22 Jun 2022)");

  script_cve_id("CVE-2022-32741", "CVE-2022-32740", "CVE-2022-32739");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Multiple Vulnerabilities (OSA-2022-09, OSA-2022-08, OSA-2022-07)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2022-32741: Attacker is able to determine if the provided username exists (and is valid)
  using Request New Password feature, based on the response time.

  - CVE-2022-32740: A reply to a forwarded email article by a 3rd party could accidentally expose
  the email content to the ticket customer under certain circumstances.

  - CVE-2022-32739: When SecureDisableBanner system configuration has been disabled and agent
  shares his calendar via public URL, received ICS file contains OTRS release number.");

  script_tag(name:"affected", value:"OTRS version 7.0.x through 7.0.34 and 8.0.x through 8.0.22.");

  script_tag(name:"solution", value:"Update to version 7.0.35, 8.0.23 or later.");

  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2022-09/");
  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2022-08/");
  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2022-07/");

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

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.0.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.35", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
