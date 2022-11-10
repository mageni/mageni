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

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118409");
  script_version("2022-11-10T08:45:27+0000");
  script_tag(name:"last_modification", value:"2022-11-10 08:45:27 +0000 (Thu, 10 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-09 12:53:13 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-28 21:31:00 +0000 (Tue, 28 Jun 2022)");

  script_cve_id("CVE-2018-25032", "CVE-2022-25313", "CVE-2022-25314", "CVE-2022-25315",
                "CVE-2022-25235", "CVE-2022-25236", "CVE-2022-23852", "CVE-2022-23990",
                "CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184", "CVE-2022-32973",
                "CVE-2022-32974", "CVE-2022-33757");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 10.2.0 Multiple Vulnerabilities (TNS-2022-11)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nessus leverages third-party software to help provide
  underlying functionality. Several of the third-party components (zlib, expat, jQuery UI)
  were found to contain vulnerabilities, and updated versions have been made available by
  the providers. Additionally, two separate vulnerabilities that utilize the Audit
  functionality were discovered, reported and fixed.

  - CVE-2022-32973: An authenticated attacker could create an audit file that bypasses PowerShell
  cmdlet checks and executes commands with administrator privileges.

  - CVE-2022-32974: An authenticated attacker could read arbitrary files from the underlying
  operating system of the scanner using a custom crafted compliance audit file without providing
  any valid SSH credentials.

  - CVE-2022-33757: An authenticated attacker could read Nessus Debug Log file attachments from the
  web UI without having the correct privileges to do so. This may lead to the disclosure of
  information on the scan target and/or the Nessus scan to unauthorized parties able to reach the
  Nessus instance.

  Nessus 10.2.0 fixes the reported Audit function and information disclosure vulnerabilities, and
  also updates zlib to version 1.2.12, expat to version 2.4.8 and jQuery UI to version 1.13.0 to
  address the remaining identified vulnerabilities.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 10.2.0.");

  script_tag(name:"solution", value:"Update to version 10.2.0 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2022-11");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "10.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.2.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
