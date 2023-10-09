# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832284");
  script_version("2023-09-22T16:08:59+0000");
  script_cve_id("CVE-2023-36796", "CVE-2023-36794", "CVE-2023-36792", "CVE-2023-36793",
                "CVE-2023-36788");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-09-22 16:08:59 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-14 11:44:15 +0530 (Thu, 14 Sep 2023)");
  script_name("Microsoft .NET Framework Multiple Vulnerabilities (KB5030180)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5030180");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Visual Studio Remote Code Execution Vulnerability.

  - .NET Framework Remote Code Execution Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution on an affected system.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 3.5, 4.8 and 4.8.1 on Microsoft Windows 10, version 22H2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5030180");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0) {
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ) {
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)) {
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build || "19045" >!< build) {
  exit(0);
}


edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer) {
  exit(0);
}

if(edgeVer =~ "^11\.0\.19041") {
  if(!registry_key_exists(key:"SOFTWARE\Microsoft\.NETFramework")) {
    if(!registry_key_exists(key:"SOFTWARE\Microsoft\ASP.NET")) {
      if(!registry_key_exists(key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\")) {
        exit(0);
      }
    }
  }

  key_list = make_list("SOFTWARE\Microsoft\.NETFramework\", "SOFTWARE\Microsoft\ASP.NET\", "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\");

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
            dllVer1 = fetch_file_version(sysPath:dotPath, file_name:"System.core.dll");
            dllVer2 = fetch_file_version(sysPath:dotPath, file_name:"System.printing.dll");

            if(dllVer1 || dllVer2)
            {
              if(dllVer2 && version_in_range(version:dllVer2, test_version:"3.0.6920.8600", test_version2:"3.0.6920.9157"))
              {
                VULN1 = TRUE ;
                vulnerable_range = "3.0.6920.8600 - 3.0.6920.9157";
                break;
              }

              else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.8", test_version2:"4.8.4661.0"))
              {
                VULN2 = TRUE ;
                vulnerable_range = "4.8 - 4.8.4661.0" ;
                break;
              }

              else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.8.9000", test_version2:"4.8.9180"))
              {
                VULN2 = TRUE ;
                vulnerable_range = "4.8.9000 - 4.8.9180" ;
                break;
              }

            }
          }
          if(vulnerable_range){
            break;
          }
        }
      }
    }
    if((!vulnerable_range) && "ASP.NET" >< key)
    {
      foreach item (registry_enum_keys(key:key))
      {
        dotPath = registry_get_sz(key:key + item, item:"Path");
        if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
        {
          dllVer1 = fetch_file_version(sysPath:dotPath, file_name:"System.core.dll");
          dllVer2 = fetch_file_version(sysPath:dotPath, file_name:"System.printing.dll");

          if(dllVer1 || dllVer2)
          {
            if(dllVer2 && version_in_range(version:dllVer2, test_version:"3.0.6920.8600", test_version2:"3.0.6920.9157"))
            {
              VULN1 = TRUE ;
              vulnerable_range = "3.0.6920.8600 - 3.0.6920.9157";
              break;
            }

            else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.8", test_version2:"4.8.4661.0"))
            {
              VULN2 = TRUE ;
              vulnerable_range = "4.8 - 4.8.4661.0" ;
              break;
            }

            else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.8.9000", test_version2:"4.8.9180"))
            {
              VULN2 = TRUE ;
              vulnerable_range = "4.8.9000 - 4.8.9180" ;
              break;
            }
          }
        }
      }
    }

    ## For versions greater than 4.5 (https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#net_b)
    if((!vulnerable_range) && "NET Framework Setup" >< key)
    {
      dotPath = registry_get_sz(key:key, item:"InstallPath");
      if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
      {
        dllVer1 = fetch_file_version(sysPath:dotPath, file_name:"System.core.dll");
        dllVer2 = fetch_file_version(sysPath:dotPath, file_name:"System.printing.dll");

        if(dllVer1 || dllVer2)
        {
          if(dllVer2 && version_in_range(version:dllVer2, test_version:"3.0.6920.8600", test_version2:"3.0.6920.9157"))
          {
            VULN1 = TRUE ;
            vulnerable_range = "3.0.6920.8600 - 3.0.6920.9157";
            break;
          }

          else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.8", test_version2:"4.8.4661.0"))
          {
            VULN2 = TRUE ;
            vulnerable_range = "4.8 - 4.8.4661.0" ;
            break;
          }

          else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.8.9000", test_version2:"4.8.9180"))
          {
            VULN2 = TRUE ;
            vulnerable_range = "4.8.9000 - 4.8.9180" ;
            break;
          }
        }
      }
    }

    if(VULN1)
    {
      report = report_fixed_ver(file_checked:dotPath + "\System.printing.dll",
                                file_version:dllVer2, vulnerable_range:vulnerable_range);
      security_message(data:report);
      exit(0);
    }

    if(VULN2)
    {
      report = report_fixed_ver(file_checked:dotPath + "\System.core.dll",
                                file_version:dllVer1, vulnerable_range:vulnerable_range);
      security_message(data:report);
      exit(0);
    }
  }
}
exit(99);
