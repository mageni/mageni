###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE Denial of Service Vulnerability-02 (jan2019-5072801) Linux
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814916");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2019-2449");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-01-16 13:13:32 +0530 (Wed, 16 Jan 2019)");
  script_name("Oracle Java SE Denial of Service Vulnerability-02 (jan2019-5072801) Linux");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Check if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  'Deployment' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to cause denial of service.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.8.0 to 1.8.0.192 on Linux.");

  script_tag(name:"solution", value:"Apply the appropriate patch from the vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/java/javase/downloads/index.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

if(jreVer =~ "^1\.8")
{
  if(version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.192"))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version: "Apply the patch", install_path:path);
    security_message(data:report);
    exit(0);
  }
}
exit(99);
