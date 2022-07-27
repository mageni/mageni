###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_officescan_mul_vulns_04_2017.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Trend Micro OfficeScan Multiple Privilege Escalation and Cross Site Scripting Vulnerabilities
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

CPE = "cpe:/a:trend_micro:office_scan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107154");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2017-5481", "CVE-2017-8801");
  script_bugtraq_id(98007);
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-26 11:00:00 +0200 (Wed, 26 Apr 2017)");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("Trend Micro OfficeScan Multiple Privilege Escalation and Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"Trend Micro OfficeScan is prone to a privilege escalation vulnerability
  and multiple cross-site scripting vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary script code in
  the browser of an unsuspecting user in the context of the affected site, steal cookie-based authentication
  credentials, access or modify data, or gain sensitive information to gain elevated privileges.");

  script_tag(name:"affected", value:"Trend Micro OfficeScan XG (12.0) and 11.0 are affected.");

  script_tag(name:"solution", value:"Trend Micro OfficeScan XG (12.0) users should update to XG CP 1352.
  Trend Micro OfficeScan XG 11.0 users should update to Version 11.0 SP1 CP 6325 .");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98007");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("General");

  script_dependencies("gb_trend_micro_office_scan_detect.nasl");
  script_mandatory_keys("Trend/Micro/Officescan/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");


if(!Ver = get_app_version(cpe:CPE)){
  exit(0);
}

if (Ver =~ "^11\.")
{
    if(version_is_equal(version: Ver, test_version:"11.0"))
    {
        fix = "11.0 SP1 CP 6325";
        VULN = TRUE;
    }
}
if (Ver =~ "^12\.")
{
  if (version_is_equal(version: Ver, test_version:"12.0"))
  {
        fix = "XG CP 1352";
        VULN = TRUE;
  }
}

if (VULN)
{
   report =  report_fixed_ver(installed_version:Ver, fixed_version:fix);
   security_message(data:report);
   exit(0);
}
exit(99);
