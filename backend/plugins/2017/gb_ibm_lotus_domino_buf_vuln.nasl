###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_domino_buf_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# IBM Lotus Domino Server Stack Buffer Overflow Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107155");

  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");

  script_tag(name:"creation_date", value:"2017-04-26 07:07:25 +0200 (Wed, 26 Apr 2017)");

  script_cve_id("CVE-2017-1274");
  script_bugtraq_id(97910);

  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("IBM Lotus Domino Server Stack Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"IBM Lotus Domino Server is prone to a stack-based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"IBM Domino is vulnerable to a stack-based buffer overflow, caused by improper bounds checking when parsing BMP images.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code within the context of the affected application. Failed exploit attempts will likely cause a denial-of-service condition.");

  script_tag(name:"affected", value:"IBM Domino 9.0.1 Fix Pack 3 (plus Interim Fixes) and earlier.
  IBM Domino 8.5.3 Fix Pack 6 (plus Interim Fixes) and earlier All 9.0 and 8.5.x releases of IBM Domino prior to those listed above.");

  script_tag(name:"solution", value:"Domino 9.0.x users should update to Domino 9.0.1 Fix Pack 3 Interim Fix 3. Domino 8.5.x users should update to Domino 8.5.3 Fix Pack 6 Interim Fix 7.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97910");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Buffer overflow");

  script_dependencies("gb_lotus_domino_detect.nasl");
  script_mandatory_keys("Domino/Version");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc"); # Used in get_highest_app_version
include("host_details.inc");

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_highest_app_version(cpe:CPE)){
  exit(0);
}

Ver = ereg_replace(pattern:"FP", string:Ver, replace:".");

if(version_in_range(version:Ver, test_version:"9.0", test_version2:"9.0.1.3")){
  fix = "9.0.1 FP3 IF3";
  VULN = TRUE;
}

if(version_in_range(version:Ver, test_version:"8.5", test_version2:"8.5.3.6")){
  fix = "8.5.3 FP6 IF7";
  VULN = TRUE;
}

if(VULN){
  report = report_fixed_ver(installed_version:Ver, fixed_version:fix);
  security_message(port:Port, data:report);
  exit(0);
}

exit(99);
