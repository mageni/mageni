# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832593");
  script_version("2024-01-22T05:07:31+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-36025", "CVE-2023-36394", "CVE-2023-36424", "CVE-2023-36393",
                "CVE-2023-36028", "CVE-2023-36719", "CVE-2023-36403", "CVE-2023-36423",
                "CVE-2023-36427", "CVE-2023-36404", "CVE-2023-36408", "CVE-2023-36047",
                "CVE-2023-24023", "CVE-2023-36405", "CVE-2023-36400", "CVE-2023-36705",
                "CVE-2023-36401", "CVE-2023-36428", "CVE-2023-36402", "CVE-2023-36425",
                "CVE-2023-36397", "CVE-2023-36017", "CVE-2023-36033", "CVE-2023-36036",
                "CVE-2023-36398");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-22 05:07:31 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-20 19:55:00 +0000 (Mon, 20 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-16 16:44:12 +0530 (Thu, 16 Nov 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5032189)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5032189");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Windows SmartScreen Security Feature Bypass Vulnerability.

  - Windows Search Service Elevation of Privilege Vulnerability.

  - Microsoft Speech Application Programming Interface (SAPI) Elevation of Privilege Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 22H2 for 32-bit Systems

  - Microsoft Windows 10 Version 22H2 for x64-based Systems

  - Microsoft Windows 10 Version 21H2 for x64-based Systems

  - Microsoft Windows 10 Version 21H2 for 32-bit Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5032189");
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

if(!("19045" >< build || "19044" >< build)) {
  exit(0);
}
dllPath = smb_get_system32root();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer) {
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"10.0.19041.3693")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"Less than 10.0.19041.3693");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);