# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832079");
  script_version("2023-06-16T05:06:18+0000");
  script_cve_id("CVE-2023-32030", "CVE-2023-29326", "CVE-2023-24895", "CVE-2023-24936",
                "CVE-2023-29331", "CVE-2023-24897", "CVE-2023-32017", "CVE-2023-32016",
                "CVE-2023-32015", "CVE-2023-32014", "CVE-2023-32011", "CVE-2023-32008",
                "CVE-2023-29373", "CVE-2023-29372", "CVE-2023-29371", "CVE-2023-29370",
                "CVE-2023-29368", "CVE-2023-29365", "CVE-2023-29364", "CVE-2023-29363",
                "CVE-2023-29362", "CVE-2023-29359", "CVE-2023-29358", "CVE-2023-29351",
                "CVE-2023-29346");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-06-16 05:06:18 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-14 11:22:33 +0530 (Wed, 14 Jun 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5027230)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5027230");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A Remote Code Execution vulnerability in Windows Resilient File System (ReFS).

  - A Remote Code Execution vulnerability in Windows Media.

  - A Remote Code Execution vulnerability in Windows Pragmatic General Multicast (PGM).

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information, bypass security restrictions, spoofing and conduct DoS
  attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5027230");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.10240.0", test_version2:"10.0.10240.19982"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.10240.0 - 10.0.10240.19982");
  security_message(data:report);
  exit(0);
}
exit(99);

