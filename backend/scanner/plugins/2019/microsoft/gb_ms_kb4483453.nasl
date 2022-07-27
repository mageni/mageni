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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814750");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2019-0657", "CVE-2019-0613");
  script_bugtraq_id(106890, 106872);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-02-13 13:34:31 +0530 (Wed, 13 Feb 2019)");
  script_name("Microsoft .NET Framework Multiple Vulnerabilities (KB4483453)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4483453");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - An error in .NET Framework when the software fails to check the source
    markup of a file.

  - An error in certain .Net Framework API's in the way they parse URL's.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to bypass security logic intended to ensure that a user-provided URL belonged
  to a specific hostname or a subdomain of that hostname and run arbitrary code
  in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 4.5.2 on

  Microsoft Windows 8.1 for 32-bit/x64

  Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4483453");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\.NETFramework")){
  if(!registry_key_exists(key:"SOFTWARE\Microsoft\ASP.NET")){
    exit(0);
  }
}

key_list = make_list("SOFTWARE\Microsoft\.NETFramework\", "SOFTWARE\Microsoft\ASP.NET\");

foreach key(key_list)
{
  if(".NETFramework" >< key)
  {
    foreach item (registry_enum_keys(key:key))
    {
      NetPath = registry_get_sz(key:key + item, item:"InstallRoot");
      if(NetPath && "\Microsoft.NET\Framework" >< NetPath)
      {
        foreach item (registry_enum_keys(key:key))
        {
          dotPath = NetPath + item;
          dllVer = fetch_file_version(sysPath:dotPath, file_name:"system.dll");
          if(dllVer)
          {
            if(version_in_range(version:dllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.36519")){
              VULN = TRUE ;
              break;
            }
          }
        }
      }
    }
  }
  if((!VULN) && "ASP.NET" >< key)
  {
    foreach item (registry_enum_keys(key:key))
    {
      dotPath = registry_get_sz(key:key + item, item:"Path");
      if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
      {
        dllVer = fetch_file_version(sysPath:dotPath, file_name:"system.dll");
        if(dllVer)
        {
          if(version_in_range(version:dllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.36519")){
            VULN = TRUE ;
            break;
          }
        }
      }
    }
  }
  if(VULN)
  {
    report = report_fixed_ver(file_checked:dotPath + "/system.dll",
                              file_version:dllVer, vulnerable_range:"4.0.30319.30000 - 4.0.30319.36519");
    security_message(data:report);
    exit(0);
  }
}
exit(99);
