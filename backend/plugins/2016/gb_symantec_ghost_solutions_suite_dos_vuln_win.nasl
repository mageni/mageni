###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_ghost_solutions_suite_dos_vuln_win.nasl 11938 2018-10-17 10:08:39Z asteins $
#
# Symantec Ghost Solutions Suite Denial of Service Vulnerability (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:symantec:ghost_solutions_suite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808573");
  script_version("$Revision: 11938 $");
  script_cve_id("CVE-2015-5689");
  script_bugtraq_id(76498);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-11 15:36:44 +0530 (Mon, 11 Jul 2016)");
  script_name("Symantec Ghost Solutions Suite Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Symantec
  Ghost Solutions Suite and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the ghostexp.exe in
  Ghost Explorer Utility performs improper sign-extend operations before array

  - element accesses.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, cause a denial of service (application
  crash), or possibly obtain sensitive information via a crafted Ghost image.");

  script_tag(name:"affected", value:"Symantec Ghost Solutions Suite (GSS) before
  3.0 HF2 (12.0.0.8010)");

  script_tag(name:"solution", value:"Update to Symantec Ghost Solutions Suite (GSS)
  3.0 HF2 (12.0.0.8010) or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20150902_00");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_ghost_solutions_suite_detect_win.nasl");
  script_mandatory_keys("Symantec/Ghost/Solution/Suite/Installed");
  script_xref(name:"URL", value:"https://symantec.flexnetoperations.com/control/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

##https://support.symantec.com/en_US/article.TECH95856.html
if(version_is_less(version:sepVer, test_version:"12.0.0.8010"))
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:"12.0.0.8010");
  security_message(data:report);
  exit(0);
}

