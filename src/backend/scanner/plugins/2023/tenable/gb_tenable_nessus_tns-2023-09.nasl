# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.170348");
  script_version("2023-03-08T10:08:50+0000");
  script_tag(name:"last_modification", value:"2023-03-08 10:08:50 +0000 (Wed, 08 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-07 09:25:18 +0000 (Tue, 07 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-05 16:07:00 +0000 (Tue, 05 Jan 2021)");

  script_cve_id("CVE-2019-11358", "CVE-2020-7656", "CVE-2020-11023", "CVE-2020-28458",
                "CVE-2021-23445", "CVE-2022-4203", "CVE-2022-4304", "CVE-2022-4450",
                "CVE-2023-0215", "CVE-2023-0216", "CVE-2023-0217", "CVE-2023-0401");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 10.5.0 Multiple Vulnerabilities (TNS-2023-09)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nessus leverages third-party software to help provide underlying
  functionality. Several of the third-party components (OpenSSL, spin.js, datatables.net) were found
  to contain vulnerabilities, and updated versions have been made available by the providers.

  Nessus 10.5.0 updates OpenSSL to version 3.0.8, spin.js to version 2.3.2 and datatables.net to
  version 1.13.2 to address the identified vulnerabilities.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 10.5.0.");

  script_tag(name:"solution", value:"Update to version 10.5.0 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-09");

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

if (version_is_less(version: version, test_version: "10.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
