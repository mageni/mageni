# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTIGDRLAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815504");
  script_version("2019-07-10T14:00:44+0000");
  script_cve_id("CVE-2019-1068");
  script_bugtraq_id(108954);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-10 14:00:44 +0000 (Wed, 10 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-10 12:14:45 +0530 (Wed, 10 Jul 2019)");
  script_name("Microsoft SQL Server 2016 SP1 GDR Remote Code Execution Vulnerability (KB4505219)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4505219");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  Microsoft SQL Server Database Engine. It incorrectly handles processing
  of internal functions.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code within the context of the SQL Server Database
  Engine service account. Failed exploit attempts may result in a
  denial-of-service condition.");

  script_tag(name:"affected", value:"Microsoft SQL Server 2016 SP1 (GDR) for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4505219");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x64" >< os_arch) {
  arch = "x64";
}
else {
  exit(0);
}

ms_sql_key = "SOFTWARE\Microsoft\Microsoft SQL Server\";
if(!registry_key_exists(key:ms_sql_key)){
  exit(0);
}

foreach item (registry_enum_keys(key:ms_sql_key))
{
  sql_path = registry_get_sz(key:ms_sql_key + item + "\Tools\Setup", item:"SQLPath");
  if(!sql_path) {
    sql_path = registry_get_sz(key:ms_sql_key + item + "\Tools\ClientSetup", item:"SQLPath");
  }
  sql_ver = registry_get_sz(key:ms_sql_key + item + "\Tools\Setup", item:"Version");
  if(!sql_ver){
    sql_ver = registry_get_sz(key:ms_sql_key + item + "\Tools\ClientSetup\CurrentVersion", item:"CurrentVersion");
  }

  if(!sql_ver){
    continue;
  }

  if("Microsoft SQL Server" >< sql_path)
  {
    sql_ver_path = "";

    if(sql_ver =~ "13\.0"){
      sql_ver_path = "SQLServer2016";
    }
    else{
      continue;
    }

    sql_path = sql_path - "Tools" + "Setup Bootstrap\" + sql_ver_path + "\" + arch;

    sysVer = fetch_file_version(sysPath:sql_path,
             file_name:"Microsoft.sqlserver.chainer.infrastructure.dll");

    if(sysVer && (sysVer =~ "^13\.0"))
    {
      if(version_in_range(version:sysVer, test_version:"13.0.4411.0", test_version2:"13.0.4258.0"))
      {
        report = report_fixed_ver(file_checked:sql_path + "\microsoft.sqlserver.chainer.infrastructure.dll",
                                  file_version:sysVer, vulnerable_range:"13.0.4411.0 - 13.0.4258.0");
        security_message(data:report);
        exit(0);
      }
    }
  }
}
