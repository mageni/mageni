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

CPE = "cpe:/a:tenable:nessus_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118414");
  script_version("2022-11-10T15:51:30+0000");
  script_tag(name:"last_modification", value:"2022-11-10 15:51:30 +0000 (Thu, 10 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-10 15:39:42 +0000 (Thu, 10 Nov 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-3602", "CVE-2022-3786");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Agent < 10.2.1 Multiple Vulnerabilities (TNS-2022-22)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_tenable_nessus_agent_detect_smb.nasl");
  script_mandatory_keys("tenable/nessus_agent/detected");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nessus Agent leverages third-party software to help provide
  underlying functionality. One of the third-party components (OpenSSL) was found to contain
  vulnerabilities, and updated versions have been made available by the providers.

  Nessus Agent 10.2.1 updates OpenSSL to version 3.0.7 to address the identified vulnerabilities.");

  script_tag(name:"affected", value:"Tenable Nessus Agent prior to version 10.2.1.");

  script_tag(name:"solution", value:"Update to version 10.2.1 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2022-22");

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

if (version_is_less(version: version, test_version: "10.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
