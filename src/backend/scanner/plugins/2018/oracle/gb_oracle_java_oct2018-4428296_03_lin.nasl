###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_oct2018-4428296_03_lin.nasl 12130 2018-10-26 13:59:17Z cfischer $
#
# Oracle Java SE Security Updates-03 (oct2018-4428296) Linux
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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814405");
  script_version("$Revision: 12130 $");
  script_cve_id("CVE-2018-3149", "CVE-2018-13785", "CVE-2018-3136", "CVE-2018-3139",
                "CVE-2018-3180");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 15:59:17 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-17 13:00:22 +0530 (Wed, 17 Oct 2018)");
  script_name("Oracle Java SE Security Updates-03 (oct2018-4428296) Linux");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Check if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to errors in components
  'JNDI', 'Deployment (libpng)', 'Security', 'Networking' and 'JSSE'.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  gain elevated privileges, cause partial denial of service conditions, partially
  modify and access data.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.6.0 to 1.6.0.201,
  1.7.0 to 1.7.0.191, 1.8.0 to 1.8.0.182, and 11 on Linux.");

  script_tag(name:"solution", value:"Apply the patch from Reference link");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/java/javase/downloads/index.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun_or_Oracle/Java/JDK_or_JRE/Linux/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE))
{
  CPE = "cpe:/a:sun:jre";
  if(!infos = get_app_version_and_location(cpe:CPE))
  {
    CPE = "cpe:/a:oracle:jdk";
    if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
  }
}

jreVer = infos['version'];
path = infos['location'];

if(jreVer =~ "^((1\.(6|7|8))|11)")
{
  if((version_in_range(version:jreVer, test_version:"1.7.0", test_version2:"1.7.0.191")) ||
     (version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.182")) ||
     (version_in_range(version:jreVer, test_version:"1.6.0", test_version2:"1.6.0.201")) ||
     (version_is_equal(version:jreVer, test_version:"11")))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version: "Apply the patch", install_path:path);
    security_message(data:report);
    exit(0);
  }
}
exit(99);
