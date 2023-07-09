# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832082");
  script_version("2023-06-16T05:06:18+0000");
  script_cve_id("CVE-2023-32019", "CVE-2023-32017", "CVE-2023-32016", "CVE-2023-32015",
                "CVE-2023-32014", "CVE-2023-32013", "CVE-2023-32012", "CVE-2023-32011",
                "CVE-2023-32009", "CVE-2023-32008", "CVE-2023-29373", "CVE-2023-29372",
                "CVE-2023-29371", "CVE-2023-29370", "CVE-2023-29368", "CVE-2023-29366",
                "CVE-2023-29365", "CVE-2023-29364", "CVE-2023-29363", "CVE-2023-29362",
                "CVE-2023-29361", "CVE-2023-29360", "CVE-2023-29359", "CVE-2023-29358",
                "CVE-2023-29352", "CVE-2023-29351", "CVE-2023-29346", "CVE-2023-24938",
                "CVE-2023-24937");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-06-16 05:06:18 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-14 11:40:38 +0530 (Wed, 14 Jun 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5027215)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5027215");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An Elevation of Privilege Vulnerability in Windows GDI.

  - An Elevation of Privilege Vulnerability in NTFS.

  - An Elevation of Privilege Vulnerability in Windows Group Policy.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 20H2 for x64-based Systems

  - Microsoft Windows 10 Version 20H2 for 32-bit Systems

  - Microsoft Windows 10 Version 21H2 for 32-bit Systems

  - Microsoft Windows 10 Version 21H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for 32-bit Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5027215");
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
key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)){
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build){
  exit(0);
}

if(!("19042" >< build || "19044" >< build || "19045" >< build)){
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

if(version_is_less(version:fileVer, test_version:"10.0.19041.3087"))
{
  report = report_fixed_ver(file_checked:dllPath + "\ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"Less than 10.0.19041.3087");
  security_message(data:report);
  exit(0);
}
exit(99);