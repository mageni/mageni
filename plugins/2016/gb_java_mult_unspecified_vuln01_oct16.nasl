###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_mult_unspecified_vuln01_oct16.nasl 63881 2016-10-20 10:41:22 Jul$
#
# Oracle Java SE Multiple Unspecified Vulnerabilities-01 Oct 2016 (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809393");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2016-5556", "CVE-2016-5568", "CVE-2016-5582", "CVE-2016-5573",
                "CVE-2016-5597", "CVE-2016-5554", "CVE-2016-5542");
  script_bugtraq_id(93618, 93621, 93623, 93628);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2016-10-21 17:29:41 +0530 (Fri, 21 Oct 2016)");
  script_name("Oracle Java SE Multiple Unspecified Vulnerabilities-01 Oct 2016 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A flaw in the 2D component.

  - A flaw in the AWT component.

  - A flaw in the Hotspot component.

  - A flaw in the Networking component.

  - A flaw in the JMX component.

  - A flaw in the Libraries component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote user
  to access and modify data on the target system, also can obtain elevated
  privileges on the target system.");

  script_tag(name:"affected", value:"Oracle Java SE 6 update 121 and prior,
  7 update 111 and prior, and 8 update 102 and prior on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE)) {
  CPE = "cpe:/a:sun:jre";
  if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
}

jreVer = infos['version'];
jrePath = infos['location'];

if(jreVer =~ "^(1\.(6|7|8))")
{
  if(version_in_range(version:jreVer, test_version:"1.6.0", test_version2:"1.6.0.121") ||
     version_in_range(version:jreVer, test_version:"1.7.0", test_version2:"1.7.0.111") ||
     version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.102"))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version:"Apply the patch", install_path:jrePath);
    security_message(data:report);
    exit(0);
  }
}
