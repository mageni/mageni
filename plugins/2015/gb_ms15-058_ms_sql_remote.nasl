###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SQL Server Multiple Vulnerabilities (3065718) - Remote
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:microsoft:sql_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805815");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2015-1761", "CVE-2015-1762", "CVE-2015-1763");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-07-15 12:57:38 +0530 (Wed, 15 Jul 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Microsoft SQL Server Multiple Vulnerabilities (3065718) - Remote");

  script_tag(name:"summary", value:"This host is missing an important
  security update according to Microsoft Bulletin MS15-058.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws exist due to,

  - An improperly casts pointers to an incorrect class.

  - An incorrectly handling internal function calls to uninitialized memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to elevate the privileges or execute arbitrary code remotely.");

  script_tag(name:"affected", value:"Microsoft SQL Server 2008 for x86/x64 Edition Service Pack 3,

  Microsoft SQL Server 2008 for x86/x64 Edition Service Pack 4,

  Microsoft SQL Server 2008 R2 for x86/x64 Edition Service Pack 2,

  Microsoft SQL Server 2008 R2 for x86/x64 Edition Service Pack 3,

  Microsoft SQL Server 2012 for x86/x64 Edition Service Pack 1,

  Microsoft SQL Server 2012 for x86/x64 Edition Service Pack 2,

  Microsoft SQL Server 2014 for x86/x64 Edition.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3065718");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-058");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

## MS SQL 2014 : sqlservr.exe : GDR x64 ==> 2014.120.2269.0  ; QFE x64 ==> 2014.120.2548.0
if(mssqlVer =~ "^12\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"12.0.2000.80", test_version2:"12.0.2268.0") ||
     version_in_range(version:mssqlVer, test_version:"12.0.2300", test_version2:"12.0.2547"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## MS SQL 2012 SP1 : sqlservr.exe : GDR x64/x86 ==> 2011.110.3156.0  ; QFE x64/x86 ==> 2011.110.3513.0
if(mssqlVer =~ "^11\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"11.00.3000.00", test_version2:"11.0.3155") ||
     version_in_range(version:mssqlVer, test_version:"11.0.3300", test_version2:"11.0.3512"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## MS SQL 2012 SP2 : sqlservr.exe : GDR x64/x86 ==> 2011.110.5343.0 ; QFE x64/x86 ==> 2011.110.5613.0
if(mssqlVer =~ "^11\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"11.0.5058.0", test_version2:"11.0.5342") ||
     version_in_range(version:mssqlVer, test_version:"11.0.5600", test_version2:"11.0.5612"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## MS SQL 2008 R2 SP2 : sqlservr.exe : GDR x64/x86 ==> 2009.100.4042.0 ; QFE x64/x86 ==> 2009.100.4339.0
if(mssqlVer =~ "^10\.50")
{
  if(version_in_range(version:mssqlVer, test_version:"10.50.4000.0", test_version2:"10.50.4041") ||
     version_in_range(version:mssqlVer, test_version:"10.50.4300", test_version2:"10.50.4338"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## MS SQL 2008 R2 SP3 : sqlservr.exe : GDR x64/x86 ==> 2009.100.6220.0  ; QFE x64/x86 ==> 2009.100.6529.0
if(mssqlVer =~ "^10\.50")
{
  if(version_in_range(version:mssqlVer, test_version:"10.50.6000.34", test_version2:"10.50.6219") ||
     version_in_range(version:mssqlVer, test_version:"10.50.6500", test_version2:"10.50.6528"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## MS SQL 2008 SP3 : sqlservr.exe : GDR x64/x86 ==> 2007.100.5538.0  ; QFE x64/x86 ==> 2007.100.5890.0
if(mssqlVer =~ "^10\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"10.00.5500.00", test_version2:"10.0.5537") ||
     version_in_range(version:mssqlVer, test_version:"10.0.5750", test_version2:"10.0.5889"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## MS SQL 2008 SP4 : sqlservr.exe : GDR x64/x86 ==> 2007.100.6241.0  ; QFE x64/x86 ==> 2007.100.6535.0
if(mssqlVer =~ "^10\.0")
{
  if(version_in_range(version:mssqlVer, test_version:"10.00.6000.29", test_version2:"10.0.6240") ||
     version_in_range(version:mssqlVer, test_version:"10.0.6500", test_version2:"10.0.6534"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
