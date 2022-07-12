###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ikarus_anti_virus_multiple_dos_vulnerabilities.nasl 8288 2018-01-04 08:04:03Z asteins $
#
# IKARUS anti.virus Multiple Denial of Service/BSOD Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112158");
  script_version("$Revision: 8288 $");
  script_cve_id("CVE-2017-17804", "CVE-2017-17795", "CVE-2017-17797");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 09:04:03 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-04 09:32:01 +0100 (Thu, 04 Jan 2018)");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");

  script_name("IKARUS anti.virus Multiple Denial of Service/BSOD Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with IKARUS anti.virus
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect" , value:"Get the installed version with the help
  of the detection NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"In IKARUS anti.virus, various driver files allow local users to cause a denial of service (BSOD)
  or possibly have unspecified other impact because of not validating input values correctly.");

  script_tag(name:"affected", value:"IKARUS anti.virus up to and including version 2.16.20.");

  script_tag(name:"solution", value:"No solution or patch is available as of 04th January, 2018.
Information regarding this issue will be updated once the solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/rubyfly/IKARUS_POC/tree/master/0x83000058");
  script_xref(name:"URL", value:"https://github.com/rubyfly/IKARUS_POC/tree/master/0x83000084");
  script_xref(name:"URL", value:"https://github.com/rubyfly/IKARUS_POC/tree/master/0x83000088");

  script_dependencies("gb_ikarus_anti_virus_detect.nasl");
  script_mandatory_keys("ikarus/anti.virus/detected", "ikarus/anti.virus/version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ikarus:anti.virus";

if(!ver = get_app_version(cpe:CPE)) {
  exit(0);
}

if(version_is_less_equal(version:ver, test_version:"2.16.20")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"None Available");
  security_message(data:report);
  exit(0);
}

exit(99);
