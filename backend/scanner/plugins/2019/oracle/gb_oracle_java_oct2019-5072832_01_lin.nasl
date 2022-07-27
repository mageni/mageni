# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815640");
  script_version("2019-10-17T05:12:29+0000");
  script_cve_id("CVE-2019-2949", "CVE-2019-2989", "CVE-2019-2958", "CVE-2019-2999",
                "CVE-2019-2962", "CVE-2019-2988", "CVE-2019-2992", "CVE-2019-2964",
                "CVE-2019-2973", "CVE-2019-2981", "CVE-2019-2978", "CVE-2019-2894",
                "CVE-2019-2983", "CVE-2019-2933", "CVE-2019-2945");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-10-17 05:12:29 +0000 (Thu, 17 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-16 10:31:47 +0530 (Wed, 16 Oct 2019)");
  script_name("Oracle Java SE Security Updates (oct2019-5072832) 01 - Linux");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to errors in
  'Kerberos', 'Networking', 'Libraries', 'Javadoc', '2D', 'Concurrency', 'JAXP',
  'Security' and 'Serialization' components.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attacker to have an impact on confidentiality, integrity and
  availability.");

  script_tag(name:"affected", value:"Oracle Java SE version 7u231(1.7.0.231) and
  earlier, 8u221(1.8.0.221) and earlier, 11.0.4 and earlier, 13 on Linux");

  script_tag(name:"solution", value:"Apply the patch");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Oracle/Java/JDK_or_JRE/Linux/detected");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE))
{
  CPE = "cpe:/a:oracle:jdk";
  if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
}

jreVer = infos['version'];
path = infos['location'];

if(!jreVer){
  exit(0);
}

if(version_in_range(version:jreVer, test_version:"1.7.0", test_version2:"1.7.0.231")||
  version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.221")||
  version_in_range(version:jreVer, test_version:"11.0", test_version2:"11.0.4")||
  version_is_equal(version:jreVer, test_version:"13.0"))
{
  report = report_fixed_ver(installed_version:jreVer, fixed_version: "Apply the patch", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
