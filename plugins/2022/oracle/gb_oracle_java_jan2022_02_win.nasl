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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819965");
  script_version("2022-01-20T06:32:54+0000");
  script_cve_id("CVE-2022-21291", "CVE-2022-21305", "CVE-2022-21360", "CVE-2022-21365",
                "CVE-2022-21282", "CVE-2022-21296", "CVE-2022-21299", "CVE-2022-21293",
                "CVE-2022-21294", "CVE-2022-21340", "CVE-2022-21341", "CVE-2022-21248");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-01-20 06:32:54 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-19 14:54:47 +0530 (Wed, 19 Jan 2022)");
  script_name("Oracle Java SE Security Update (jan2022) 02 - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple unspecified
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified
  errors in components 'Serialization', 'Libraries', 'JAXP', 'ImageIO' and 'Hotspot'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to have an impact on availability, integrity and confidentiality.");

  script_tag(name:"affected", value:"Oracle Java SE version 8u311 (1.8.0.311)
  and earlier, 7u321 (1.7.0.321) and earlier, 11.x through 11.0.13 and 17.x
  through 17.01 on Windows.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2022.html#AppendixJAVA");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:oracle:jre";

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.311") ||
   version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.321") ||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.13") ||
   version_in_range(version:vers, test_version:"17.0", test_version2:"17.01"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version: "Apply the patch", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
