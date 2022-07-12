###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_integration_bus_xxe_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# IBM Integration Bus XXE Privilege Escalation Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:integration_bus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810802");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2016-9706");
  script_bugtraq_id(96274);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-13 16:01:06 +0530 (Mon, 13 Mar 2017)");
  script_name("IBM Integration Bus XXE Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is installed with IBM Integration
  Bus and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an XML External Entity
  Injection (XXE) error when processing XML data.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to expose highly sensitive information or consume all available memory resources.");

  script_tag(name:"affected", value:"IBM Integration Bus 9.0 through 9.0.0.5
  and 10.0 through 10.0.0.4");

  script_tag(name:"solution", value:"Upgrade to IBM Integration Bus 9.0.0.6
  or 10.0.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21997918");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24042598");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24042299");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_ibm_integration_bus_detect.nasl");
  script_mandatory_keys("IBM/Integration/Bus/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ibVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(ibVer =~ "^9\.0")
{
  if(version_in_range(version:ibVer, test_version:"9.0.0.0", test_version2:"9.0.0.5"))
  {
    fix = "9.0.0.6";
    VULN = TRUE;
  }
}

else if(ibVer =~ "^10\.0")
{
  if(version_in_range(version:ibVer, test_version:"10.0.0.0", test_version2:"10.0.0.4"))
  {
    fix = "10.0.0.5";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:ibVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
