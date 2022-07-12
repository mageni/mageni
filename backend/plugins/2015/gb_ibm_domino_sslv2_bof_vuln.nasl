###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_domino_sslv2_bof_vuln.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# IBM Domino SSLv2 'nldap.exe' Buffer Overflow Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805548");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2015-0134");
  script_bugtraq_id(73912);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-08 15:03:56 +0530 (Fri, 08 May 2015)");
  script_name("IBM Domino SSLv2 'nldap.exe' Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"This host is installed with IBM Domino and
  is prone to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to overflow condition in
  'nldap.exe' as user-supplied input is not properly validated when handling a
  Client Master Key Message packet.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a buffer overflow, resulting in a denial of service or
  potentially allowing the execution of arbitrary code.");

  script_tag(name:"affected", value:"IBM Domino 8.5.x before 8.5.1 FP5 IF3, 8.5.2
  before FP4 IF3, 8.5.3 before FP6 IF6, 9.0 before IF7, and 9.0.1 before FP2 IF3.");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 8.5.1 FP5 IF3 or 8.5.2
  FP4 IF3 or 8.5.3 FP6 IF6 or 9.0 IF7 or 9.0.1 FP2 IF3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21700029");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
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

if(version_in_range(version:domVer1, test_version:"8.5", test_version2:"8.5.1.5"))
{
  fix = "8.5.1 FP5 IF3";
  VULN = TRUE;
}

if(version_in_range(version:domVer1, test_version:"8.5.2", test_version2:"8.5.2.4"))
{
  fix = "8.5.2 FP4 IF3";
  VULN = TRUE;
}

if(version_in_range(version:domVer1, test_version:"8.5.3", test_version2:"8.5.3.6"))
{
  fix = "8.5.3 FP6 IF6";
  VULN = TRUE;
}

if(version_is_equal(version:domVer1, test_version:"9.0"))
{
  fix = "9.0 IF7";
  VULN = TRUE;
}

if(version_in_range(version:domVer1, test_version:"9.0.1", test_version2:"9.0.1.2"))
{
  fix = "9.0.1 FP2 IF3";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed Version: ' + domVer + '\nFixed Version: ' + fix + '\n';
  security_message(data:report, port:0);
  exit(0);
}
