###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_domino_dos_vuln_mar16.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# IBM Domino Denial of Service Vulnerability - Mar16
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807619");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2014-0822");
  script_bugtraq_id(65427);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-21 19:13:44 +0530 (Mon, 21 Mar 2016)");
  script_name("IBM Domino Denial of Service Vulnerability - Mar16");

  script_tag(name:"summary", value:"This host is installed with IBM Domino and
  is prone to denial of service vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified
  error in IMAP server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to cause denial of service.");

  script_tag(name:"affected", value:"IBM Domino 8.5.x before 8.5.3 FP6 IF1 and
  9.0.x before 9.0.1 FP1");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 IF1,
  or 9.0.1 FP1, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21663023");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_lotus_domino_detect.nasl");
  script_mandatory_keys("Domino/Version");
  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc"); # Used in get_highest_app_version
include("host_details.inc");

if(!domVer = get_highest_app_version(cpe:CPE)){
  exit(0);
}

domVer1 = ereg_replace(pattern:"FP", string:domVer, replace: ".");

if(version_in_range(version:domVer1, test_version:"8.5", test_version2:"8.5.3.6"))
{
  fix = "8.5.3 FP6 IF1";
  VULN = TRUE;
}

if(version_in_range(version:domVer1, test_version:"9.0.0", test_version2:"9.0.1.0"))
{
  fix = "9.0.1 FP1";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:domVer, fixed_version:fix);
  security_message(data:report, port:0);
  exit(0);
}
