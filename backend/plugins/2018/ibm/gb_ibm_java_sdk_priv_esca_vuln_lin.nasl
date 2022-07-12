###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Java SDK Remote Privilege Escalation Vulnerability (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ibm:java_sdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813819");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-1417");
  script_bugtraq_id(103216);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-09 14:03:02 +0530 (Thu, 09 Aug 2018)");
  script_name("IBM Java SDK Remote Privilege Escalation Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with IBM Java SDK
  and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified flaw
  in the J9 JVM.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to gain elevated privileges on an affected system.");

  script_tag(name:"affected", value:"IBM SDK, Java Technology Edition 7.1 before
  7.1.4.20 and 8.0 before 8.0.5.10.");

  script_tag(name:"solution", value:"Upgrade to IBM Java SDK 7.1.4.20 or 8.0.5.10
  or later. Please see the references for more information.");

  script_xref(name:"URL", value:"https://www.securitytracker.com/id/1040403");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04021");
  script_xref(name:"URL", value:"https://www.ibm.com/developerworks/java/jdk");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("IBM/Java/SDK/Linux/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
javaVer = infos['version'];
javaPath = infos['location'];

if(javaVer =~ "^7\.1" && version_is_less(version:javaVer, test_version:"7.1.4.20")){
  fix = "7.1.4.20";
}
else if(javaVer =~ "^8\.0" && version_is_less(version:javaVer, test_version:"8.0.5.10")){
  fix = "8.0.5.10";
}

if(fix)
{
  report = report_fixed_ver(installed_version:javaVer, fixed_version:fix, install_path:javaPath);
  security_message(data:report);
  exit(0);
}
