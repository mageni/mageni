# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832241");
  script_version("2023-08-11T05:05:41+0000");
  script_cve_id("CVE-2023-36873", "CVE-2023-36899");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-09 10:42:05 +0530 (Wed, 09 Aug 2023)");
  script_name("Microsoft .NET Framework Multiple Vulnerabilities (KB5029654)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5029654");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - .NET Framework Spoofing Vulnerability.

  - ASP.NET Elevation of Privilege Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct spoofing or privilege escalation on an affected system.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 2.0, 3.0, 4.6.2, 4.7, 4.7.1, 4.7.2 for Microsoft Windows Server 2008 SP2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5029654");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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

if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0) {
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\.NETFramework")) {
  if(!registry_key_exists(key:"SOFTWARE\Microsoft\ASP.NET")) {
    if(!registry_key_exists(key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\")) {
      exit(0);
    }
  }
}

key_list = make_list("SOFTWARE\Microsoft\.NETFramework\", "SOFTWARE\Microsoft\ASP.NET\", "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\");

foreach key(key_list) {
  if(".NETFramework" >< key) {
    foreach item (registry_enum_keys(key:key)) {
      NetPath = registry_get_sz(key:key + item, item:"InstallRoot");
      if(NetPath && "\Microsoft.NET\Framework" >< NetPath) {
        foreach item (registry_enum_keys(key:key)) {
          dotPath = NetPath + item;
          dllVer1 = fetch_file_version(sysPath:dotPath, file_name:"Mscorlib.dll");
          dllVer2 = fetch_file_version(sysPath:dotPath, file_name:"System.printing.dll");
          if(dllVer1 || dllVer2)
          {
            if(dllVer1 && version_in_range(version:dllVer1, test_version:"2.0.50727", test_version2:"2.0.50727.8973"))
            {
              vulnerable_range1 = "2.0.50727 - 2.0.50727.8973";
              break;
            }

            else if(dllVer2 && version_in_range(version:dllVer2, test_version:"3.0.6920.8600", test_version2:"3.0.6920.8954"))
            {
              vulnerable_range2 = "3.0.6920.8600 - 3.0.6920.8954";
              break;
            }

            else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.6", test_version2:"4.7.4050"))
            {
              vulnerable_range1 = "4.6 - 4.7.4050";
              break;
            }
          }
        }
        if(vulnerable_range1 || vulnerable_range2){
          break;
        }
      }
    }

  }

  if(!vulnerable_range1 && vulnerable_range2 && "ASP.NET" >< key)
  {
    foreach item (registry_enum_keys(key:key))
    {
      dotPath = registry_get_sz(key:key + item, item:"Path");
      if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
      {
        dllVer1 = fetch_file_version(sysPath:dotPath, file_name:"Mscorlib.dll");
        dllVer2 = fetch_file_version(sysPath:dotPath, file_name:"System.printing.dll");
        if(dllVer1 || dllVer2)
        {
          if(dllVer1 && version_in_range(version:dllVer1, test_version:"2.0.50727", test_version2:"2.0.50727.8973"))
          {
            vulnerable_range1 = "2.0.50727 - 2.0.50727.8973";
            break;
          }
          else if(dllVer2 && version_in_range(version:dllVer2, test_version:"3.0.6920.8600", test_version2:"3.0.6920.8954"))
          {
            vulnerable_range2 = "3.0.6920.8600 - 3.0.6920.8954";
            break;
          }

          else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.6", test_version2:"4.7.4050"))
          {
            vulnerable_range1 = "4.6 - 4.7.4050";
            break;
          }
        }
      }
    }
  }

  ## For versions greater than 4.5 (https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#net_b)
  if(!vulnerable_range1 && vulnerable_range2 && "NET Framework Setup" >< key)
  {
    dotPath = registry_get_sz(key:key, item:"InstallPath");
    if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
    {
      dllVer1 = fetch_file_version(sysPath:dotPath, file_name:"Mscorlib.dll");
      dllVer2 = fetch_file_version(sysPath:dotPath, file_name:"System.printing.dll");
      if(dllVer1 || dllVer2)
      {
        if(dllVer1 && version_in_range(version:dllVer1, test_version:"2.0.50727", test_version2:"2.0.50727.8973"))
        {
          vulnerable_range1 = "2.0.50727 - 2.0.50727.8973";
          break;
        }

        else if(dllVer2 && version_in_range(version:dllVer2, test_version:"3.0.6920.8600", test_version2:"3.0.6920.8954"))
        {
          vulnerable_range2 = "3.0.6920.8600 - 3.0.6920.8954";
          break;
        }

        else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.6", test_version2:"4.7.4050"))
        {
          vulnerable_range1 = "4.6 - 4.7.4050";
          break;
        }
      }
    }
  }

  if(vulnerable_range1) {
    report = report_fixed_ver(file_checked:dotPath + "Mscorlib.dll",
                              file_version:dllVer1, vulnerable_range:vulnerable_range1);
    security_message(port:0, data:report);
    exit(0);
  }
  else if(vulnerable_range2) {
    report = report_fixed_ver(file_checked:dotPath + "System.printing.dll",
                              file_version:dllVer2, vulnerable_range:vulnerable_range2);
    security_message(port:0, data:report);
    exit(0);
  }

}
exit(99);
