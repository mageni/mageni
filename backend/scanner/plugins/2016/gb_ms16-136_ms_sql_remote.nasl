###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SQL Server Multiple Vulnerabilities (3199641)
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

CPE = "cpe:/a:microsoft:sql_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809096");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2016-7249", "CVE-2016-7250", "CVE-2016-7251", "CVE-2016-7252",
		"CVE-2016-7253", "CVE-2016-7254");
  script_bugtraq_id(94037, 94060, 94043, 94050, 94061, 94056);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-11-14 15:30:37 +0530 (Mon, 14 Nov 2016)");
  script_name("Microsoft SQL Server Multiple Vulnerabilities (3199641)");

  script_tag(name:"summary", value:"This host is missing an important
  security update according to Microsoft Bulletin MS16-136.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The Microsoft SQL Server improperly handles pointer casting.

  - The SQL Server MDS does not properly validate a request parameter on the SQL
    Server site.

  - An improper check of 'FILESTREAM' path.

  - The SQL Server Agent incorrectly check ACLs on atxcore.dll.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges that could be used to view, change,
  or delete data, or create new accounts, also can gain additional database and
  file information and to spoof content, disclose information, or take any action
  that the user could take on the site on behalf of the targeted user.");

  script_tag(name:"affected", value:"Microsoft SQL Server 2012 x86/x64 Edition Service Pack 2 and prior,

  Microsoft SQL Server 2012 x86/x64 Edition Service Pack 3 and prior,

  Microsoft SQL Server 2014 x86/x64 Edition Service Pack 1 and prior,

  Microsoft SQL Server 2014 x86/x64 Edition Service Pack 2 and prior,

  Microsoft SQL Server 2016 x64 Edition.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-136");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("mssqlserver_detect.nasl");
  script_mandatory_keys("MS/SQLSERVER/Running");
  script_require_ports(1433);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!mssqlPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mssqlVer = get_app_version(cpe:CPE, port:mssqlPort)){
  exit(0);
}

## MS SQL 2012 SP2 : GDR x64/x86 ==> 11.0.5388.0  ; CU x64/x86 ==> 11.0.5676.0
if(mssqlVer =~ "^11\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"11.0.5400.0", test_version2:"11.0.5675.0"))
  {
    VULN = TRUE;
    vulnerable_range = "11.0.5400.0 - 11.0.5675.0";
  }
  else if(version_in_range(version:mssqlVer, test_version:"11.0.5058.0", test_version2:"11.0.5387.0"))
  {
    VULN = TRUE;
    vulnerable_range = "11.0.5000.0 - 11.0.5387.0";
  }
}

## MS SQL 2012 SP3 : GDR x64/x86 ==> 11.0.6248.0   ; CU x64/x86 ==> 11.0.6567.0
else if(mssqlVer =~ "^11\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"11.0.6000.0", test_version2:"11.0.6247.0"))
  {
    VULN = TRUE;
    vulnerable_range = "11.0.6000.0 - 11.0.6247.0";
  }
  else if(version_in_range(version:mssqlVer, test_version:"11.0.6400.0", test_version2:"11.0.6566.0"))
  {
    VULN = TRUE;
    vulnerable_range = "11.0.6400.0 - 11.0.6566.0";
  }
}

## MS SQL 2014 SP1 : GDR x64/x86 ==> 12.0.4487.0   ; CU x64/x86 ==> 12.0.4232.0
else if(mssqlVer =~ "^12\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"12.0.4000.0", test_version2:"12.0.4231.0"))
  {
    VULN = TRUE;
    vulnerable_range = "12.0.4000.0 - 12.0.4231.0";
  }
  else if(version_in_range(version:mssqlVer, test_version:"12.0.4300.0", test_version2:"12.0.4486.0"))
  {
    VULN = TRUE;
    vulnerable_range = "12.0.4300.0 - 12.0.4486.0";
  }
}

## MS SQL 2014 SP2 : GDR x64/x86 ==> 12.0.5203.0   ; CU x64/x86 ==> 12.0.5532.0
else if(mssqlVer =~ "^12\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"12.0.5000.0", test_version2:"12.0.5202.0"))
  {
    VULN = TRUE;
    vulnerable_range = "12.0.5000.0 - 12.0.5202.0";
  }
  else if(version_in_range(version:mssqlVer, test_version:"12.0.5400.0", test_version2:"12.0.5531.0"))
  {
    VULN = TRUE;
    vulnerable_range = "12.0.5400.0 - 12.0.5531.0";
  }
}

## MS SQL 2016 : GDR x64/x86 ==> 13.0.1722.0 ; CU x64/x86 ==> 13.0.2185.3
else if(mssqlVer =~ "^13\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"13.0.1000.0", test_version2:"13.0.1721.0"))
  {
    VULN = TRUE;
    vulnerable_range = "13.0.1000.0 - 13.0.1721.0";
  }
  else if(version_in_range(version:mssqlVer, test_version:"13.0.2000.0", test_version2:"13.0.2185.2"))
  {
    VULN = TRUE;
    vulnerable_range = "13.0.2000.0 - 13.0.2185.2";
  }
}

if(VULN)
{
  report  = 'Vulnerable range: ' + vulnerable_range + '\n' ;
  security_message(data:report, port:mssqlPort);
  exit(0);
}
