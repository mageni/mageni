###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SQL Server Elevation of Privilege Vulnerability (2984340)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802080");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-1820", "CVE-2014-4061");
  script_bugtraq_id(69071, 69088);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-08-13 17:35:15 +0530 (Wed, 13 Aug 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft SQL Server Elevation of Privilege Vulnerability (2984340)");


  script_tag(name:"summary", value:"This host is missing an important security update according to
Microsoft Bulletin MS14-044");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws are due to when,

  - SQL Master Data Services (MDS) does not properly encode output.

  - SQL Server processes an incorrectly formatted T-SQL query.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a Denial
of Service or elevation of privilege.");
  script_tag(name:"affected", value:"Microsoft SQL Server 2014 x64 Edition
Microsoft SQL Server 2012 x86/x64 Edition Service Pack 1 and prior
Microsoft SQL Server 2008 R2 x86/x64 Edition Service Pack 2 and prior
Microsoft SQL Server 2008 x86/x64 Edition Service Pack 3 and prior");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-044");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x64" >< os_arch){
  arch = "x64";
}
else if("x86" >< os_arch){
  arch = "x86";
}
else{
  exit(0);
}

ms_sql_key = "SOFTWARE\Microsoft\Microsoft SQL Server\";
if(!registry_key_exists(key:ms_sql_key)){
  exit(0);
}

## C:\Program Files\Microsoft SQL Server\120\Setup Bootstrap\SQLServer2014\x64
foreach item (registry_enum_keys(key:ms_sql_key))
{
  sql_path = registry_get_sz(key:ms_sql_key + item + "\Tools\Setup", item:"SQLPath");
  sql_ver = registry_get_sz(key:ms_sql_key + item + "\Tools\Setup", item:"Version");

  if(!sql_ver){
    continue;
  }

  if("Microsoft SQL Server" >< sql_path)
  {
    ## Reset the string
    sql_ver_path = "";

    if(sql_ver =~ "12\.0"){
      sql_ver_path = "SQLServer2014";
    }
    else if(sql_ver =~ "11\.0"){
      sql_ver_path = "SQLServer2012";
    }
    else if(sql_ver =~ "10\.50"){
      sql_ver_path = "SQLServer2008R2";
    }
    else if(sql_ver =~ "10\.0"){
      sql_ver_path = "SQLServer2008";
    }
    else {
      continue;
    }

    ## We have taken arch path for "x86" on assumtion and some google
    ## but not sure about the file path in case in "x86", we need to update the
    ## path if it's different.
    sql_path = sql_path - "Tools\" + "Setup Bootstrap\" + sql_ver_path + "\" + arch;

    sysVer = fetch_file_version(sysPath:sql_path,
             file_name:"Microsoft.sqlserver.chainer.infrastructure.dll");

    if(sysVer)
    {
      ## MS SQL 2014 : GDR x64 ==> 12.0.2254.0  ; QFE x64 ==> 12.0.2381.0
      if(sysVer =~ "^12\.0")
      {
        if(version_in_range(version:sysVer, test_version:"12.0.2000", test_version2:"12.0.2253") ||
           version_in_range(version:sysVer, test_version:"12.0.2300", test_version2:"12.0.2380"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      ## MS SQL 2012 SP1 : GDR x64/x86 ==> 11.0.3153.0  ; QFE x64/x86 ==> 11.0.3460.0
      if(sysVer =~ "^11\.0")
      {
        if(version_in_range(version:sysVer, test_version:"11.0.3000", test_version2:"11.0.3152") ||
           version_in_range(version:sysVer, test_version:"11.0.3300", test_version2:"11.0.3459"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      ## MS SQL 2008 R2 SP2 : GDR x64/x86 ==> 10.50.4033.0 ; QFE x64/x86 ==> 10.50.4321.0
      if(sysVer =~ "^10\.50")
      {
        if(version_in_range(version:sysVer, test_version:"10.50.4000", test_version2:"10.50.4032") ||
           version_in_range(version:sysVer, test_version:"10.50.4251", test_version2:"10.50.4320"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      ## MS SQL 2008 SP3 : GDR x64/x86 ==> 10.0.5520.0  ; QFE x64/x86 ==> 10.0.5869.0
      if(sysVer =~ "^10\.0")
      {
        if(version_in_range(version:sysVer, test_version:"10.0.5500", test_version2:"10.0.5519") ||
           version_in_range(version:sysVer, test_version:"10.0.5750", test_version2:"10.0.5868"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}
