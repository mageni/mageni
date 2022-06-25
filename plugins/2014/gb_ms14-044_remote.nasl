###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SQL Server Elevation of Privilege Vulnerability (2984340) - Remote
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805110");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2014-1820", "CVE-2014-4061");
  script_bugtraq_id(69071, 69088);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-12-01 16:03:48 +0530 (Mon, 01 Dec 2014)");
  script_name("Microsoft SQL Server Elevation of Privilege Vulnerability (2984340) - Remote");

  script_tag(name:"summary", value:"This host is missing an important
  security update according to Microsoft Bulletin MS14-044.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to when,

  - SQL Master Data Services (MDS) does not properly encode output.

  - SQL Server processes an incorrectly formatted T-SQL query.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a Denial of Service or elevation of privilege.");

  script_tag(name:"affected", value:"Microsoft SQL Server 2014 x64 Edition,

  Microsoft SQL Server 2012 x86/x64 Edition Service Pack 1 and prior,

  Microsoft SQL Server 2008 R2 x86/x64 Edition Service Pack 2 and prior,

  Microsoft SQL Server 2008 x86/x64 Edition Service Pack 3 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-044");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

## MS SQL 2014 : GDR x64 ==> 12.0.2254.0  ; QFE x64 ==> 12.0.2381.0
if(mssqlVer =~ "^12\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"12.0.2000", test_version2:"12.0.2253") ||
     version_in_range(version:mssqlVer, test_version:"12.0.2300", test_version2:"12.0.2380"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## MS SQL 2012 SP1 : GDR x64/x86 ==> 11.0.3153.0  ; QFE x64/x86 ==> 11.0.3460.0
if(mssqlVer =~ "^11\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"11.0.3000", test_version2:"11.0.3152") ||
     version_in_range(version:mssqlVer, test_version:"11.0.3300", test_version2:"11.0.3459"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## MS SQL 2008 R2 SP2 : GDR x64/x86 ==> 10.50.4033.0 ; QFE x64/x86 ==> 10.50.4321.0
if(mssqlVer =~ "^10\.50")
{
  if(version_in_range(version:mssqlVer, test_version:"10.50.4000", test_version2:"10.50.4032") ||
     version_in_range(version:mssqlVer, test_version:"10.50.4251", test_version2:"10.50.4320"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## MS SQL 2008 SP3 : GDR x64/x86 ==> 10.0.5520.0  ; QFE x64/x86 ==> 10.0.5869.0
if(mssqlVer =~ "^10\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"10.0.5500", test_version2:"10.0.5519") ||
     version_in_range(version:mssqlVer, test_version:"10.0.5750", test_version2:"10.0.5868"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
