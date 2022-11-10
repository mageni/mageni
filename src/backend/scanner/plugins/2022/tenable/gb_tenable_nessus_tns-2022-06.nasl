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
  script_oid("1.3.6.1.4.1.25623.1.0.118407");
  script_version("2022-11-09T08:42:18+0000");
  script_tag(name:"last_modification", value:"2022-11-09 08:42:18 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-08 15:11:52 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 06:15:00 +0000 (Tue, 22 Mar 2022)");

  script_cve_id("CVE-2022-0778");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 8.15.4, 10.x < 10.1.2 DoS Vulnerability (TNS-2022-06)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");

  script_tag(name:"summary", value:"Tenable Nessus is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nessus leverages third-party software to help provide
  underlying functionality. One of the third-party components (OpenSSL) was found to
  contain a vulnerability, and an updated version has been made available by the provider.
  Nessus 8.15.4 and Nessus 10.1.2 update OpenSSL to version 1.1.1n to address the
  identified vulnerability.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 8.15.4, 10.1.2.");

  script_tag(name:"solution", value:"Update to version 8.15.4, 10.1.2 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2022-06");

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

if (version_is_less(version: version, test_version: "8.15.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.15.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^10\." && version_is_less(version: version, test_version: "10.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
