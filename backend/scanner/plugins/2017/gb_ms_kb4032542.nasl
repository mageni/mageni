###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SQL Server 2014 Information Disclosure Vulnerability (KB4032542)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811285");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-8516");
  script_bugtraq_id(100041);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-08-09 15:23:11 +0530 (Wed, 09 Aug 2017)");
  script_name("Microsoft SQL Server 2014 Information Disclosure Vulnerability (KB4032542)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4032542");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in Microsoft
  SQL Server Analysis Services when it improperly enforces permissions.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to sensitive information and access to an affected SQL server
  database.");

  script_tag(name:"affected", value:"Microsoft SQL Server 2014 Service Pack 1 for x86/x64-based Systems (CU)");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4032542");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## OS Architecture
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
    else{
      continue;
    }

    ## TODO: We have taken arch path for "x86" on assumtion and some google
    ## but not sure about the file path in case in "x86", we need to update the
    ## path if it's different.
    sql_path = sql_path - "Tools\" + "Setup Bootstrap\" + sql_ver_path + "\" + arch;

    sysVer = fetch_file_version(sysPath:sql_path,
             file_name:"Microsoft.sqlserver.chainer.infrastructure.dll");

    ## security update for SQL Server 2014 Service Pack 1 CU
    if(sysVer =~ "^(12\.0)")
    {
      if(version_in_range(version:sysVer, test_version:"12.0.4300.0", test_version2:"12.0.4521.0"))
      {
        report = 'File checked:     ' + sql_path + "\microsoft.sqlserver.chainer.infrastructre.dll" + '\n' +
                 'File version:     ' + sysVer  + '\n' +
                 'Vulnerable range: 12.0.4300.0 - 12.0.4521.0\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}
exit(0);
