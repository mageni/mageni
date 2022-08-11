###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE Security Updates (apr2018-3678067) 05 - Windows
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
  script_oid("1.3.6.1.4.1.25623.1.0.813305");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-2796", "CVE-2018-2799");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-04-18 19:07:58 +0530 (Wed, 18 Apr 2018)");
  script_name("Oracle Java SE Security Updates (apr2018-3678067) 05 - Windows");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  unspecified errors in 'Concurrency' and 'JAXP' components of Java SE.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to affect availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.8.0.162 and earlier,
  1.7.0.171 and earlier, 10.0 on Windows");

  script_tag(name:"solution", value:"Apply the appropriate patch from the vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE)) {
  CPE = "cpe:/a:sun:jre";
  if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
}

jreVer = infos['version'];
path = infos['location'];

if(jreVer =~ "^(1\.[7|8]|10)\.")
{
  if((version_in_range(version:jreVer, test_version:"1.7.0", test_version2:"1.7.0.171")) ||
     (version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.162")) ||
     (jreVer =~ "^10" && version_is_less(version:jreVer, test_version:"10.0.1")))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version: "Apply the patch", install_path:path);
    security_message(data:report);
    exit(0);
  }
}
exit(0);
