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

CPE = "cpe:/a:tenable:nessus_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144902");
  script_version("2020-11-09T03:18:33+0000");
  script_tag(name:"last_modification", value:"2020-11-09 11:47:04 +0000 (Mon, 09 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-09 03:09:03 +0000 (Mon, 09 Nov 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2020-5793");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Agent 8.0.0 - 8.1.0 Arbitrary Code Execution vulnerability (TNS-2020-07)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_tenable_nessus_agent_detect_smb.nasl");
  script_mandatory_keys("tenable/nessus_agent/detected");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to a local arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in Nessus Agent for Windows could allow an authenticated local
  attacker to execute arbitrary code by copying user-supplied files to a specially constructed path in a
  specifically named user directory.");

  script_tag(name:"impact", value:"A local authenticated attacker my execute arbitrary code. The attacker needs
  valid credentials on the Windows system to exploit this vulnerability.");

  script_tag(name:"affected", value:"Tenable Nessus Agent versions 8.0.0 - 8.1.0.");

  script_tag(name:"solution", value:"Update to version 8.1.1 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2020-07");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
