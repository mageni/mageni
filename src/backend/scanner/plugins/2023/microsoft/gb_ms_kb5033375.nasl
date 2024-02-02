# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832642");
  script_version("2023-12-14T08:20:35+0000");
  script_cve_id("CVE-2023-20588", "CVE-2023-21740", "CVE-2023-35628", "CVE-2023-35630",
                "CVE-2023-35631", "CVE-2023-35634", "CVE-2023-35635", "CVE-2023-35639",
                "CVE-2023-35641", "CVE-2023-35642", "CVE-2023-35644", "CVE-2023-36003",
                "CVE-2023-36004", "CVE-2023-36005", "CVE-2023-36006", "CVE-2023-36011",
                "CVE-2023-36391", "CVE-2023-36696");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-14 08:20:35 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 18:58:00 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-13 11:16:35 +0530 (Wed, 13 Dec 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5033375)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5033375");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability.

  - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability.

  - Windows Media Remote Code Execution Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation would allow an
  attacker to elevate privileges, execute arbitrary commands, disclose information
  and conduct DoS attacks on an affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows 11 version 22H2 for x64-based Systems

  - Microsoft Windows 11 Version 23H2 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5033375");
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

if(hotfix_check_sp(win11:1) <= 0) {
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)) {
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build || (build != "22621" && build != "22631")) {
  exit(0);
}

dllPath = smb_get_systemroot();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"\system32\ntoskrnl.exe");
if(!fileVer) {
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.22621.0", test_version2:"10.0.22621.2860")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\ntoskrnl.exe", file_version:fileVer,
                            vulnerable_range:"10.0.22621.0 - 10.0.22621.2860");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
