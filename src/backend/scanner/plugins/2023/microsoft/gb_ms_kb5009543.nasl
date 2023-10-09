# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832417");
  script_version("2023-10-06T16:09:51+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-21913", "CVE-2022-21901", "CVE-2022-21897", "CVE-2022-21889",
                "CVE-2022-21888", "CVE-2022-21885", "CVE-2022-21963", "CVE-2022-21924",
                "CVE-2022-21959", "CVE-2022-21900", "CVE-2022-21958", "CVE-2022-21882",
                "CVE-2022-21906", "CVE-2022-21881", "CVE-2022-21874", "CVE-2022-21898",
                "CVE-2022-21912", "CVE-2022-21910", "CVE-2022-21905", "CVE-2022-21902",
                "CVE-2022-21884", "CVE-2022-21908", "CVE-2022-21907", "CVE-2022-21896",
                "CVE-2022-21894", "CVE-2022-21893", "CVE-2022-21892", "CVE-2022-21890",
                "CVE-2022-21960", "CVE-2022-21904", "CVE-2022-21879", "CVE-2022-21962",
                "CVE-2022-21928", "CVE-2022-21883", "CVE-2022-21878", "CVE-2022-21961",
                "CVE-2022-21843", "CVE-2022-21880", "CVE-2022-21877", "CVE-2022-21876",
                "CVE-2022-21875", "CVE-2022-21873", "CVE-2022-21872", "CVE-2022-21870",
                "CVE-2022-21869", "CVE-2022-21868", "CVE-2022-21867", "CVE-2022-21866",
                "CVE-2022-21865", "CVE-2022-21864", "CVE-2022-21863", "CVE-2022-21862",
                "CVE-2022-21861", "CVE-2022-21860", "CVE-2022-21859", "CVE-2022-21858",
                "CVE-2022-21857", "CVE-2022-21838", "CVE-2022-21836", "CVE-2022-21835",
                "CVE-2022-21834", "CVE-2022-21833", "CVE-2022-21915", "CVE-2022-21914",
                "CVE-2022-21895", "CVE-2022-21916", "CVE-2022-21918", "CVE-2022-21919",
                "CVE-2021-36976", "CVE-2021-22947", "CVE-2022-21852", "CVE-2022-21851",
                "CVE-2022-21850", "CVE-2022-21849", "CVE-2022-21848", "CVE-2022-21871",
                "CVE-2022-21920", "CVE-2022-21921", "CVE-2022-21922", "CVE-2022-21847");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-18 19:43:00 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2023-08-23 11:09:03 +0530 (Wed, 23 Aug 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5009543)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5009543");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An Elevation of Privilege Vulnerability in Windows Hyper-V.

  - An Elevation of Privilege Vulnerability in Windows Common Log File System Driver.

  - An Elevation of Privilege Vulnerability in Windows Remote Access Connection Manager.

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
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5009543");
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

if(version_is_less(version:fileVer, test_version:"10.0.19041.1466")) {
  report = report_fixed_ver(file_checked:dllPath + "\ntoskrnl.exe", file_version:fileVer, vulnerable_range:"Less than 10.0.19041.1466");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);