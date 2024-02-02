# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832767");
  script_version("2024-01-19T16:09:33+0000");
  script_cve_id("CVE-2024-21320", "CVE-2024-21307", "CVE-2024-21306", "CVE-2024-21305",
                "CVE-2024-20697", "CVE-2024-20692", "CVE-2024-20687", "CVE-2024-20683",
                "CVE-2024-21316", "CVE-2024-20660", "CVE-2024-20652", "CVE-2024-20658",
                "CVE-2024-20653", "CVE-2024-20674", "CVE-2024-20666", "CVE-2024-21310",
                "CVE-2024-21314", "CVE-2024-21313", "CVE-2024-21311", "CVE-2024-21309",
                "CVE-2024-20700", "CVE-2024-20699", "CVE-2024-20698", "CVE-2024-20696",
                "CVE-2024-20694", "CVE-2024-20691", "CVE-2024-20690", "CVE-2024-20682",
                "CVE-2024-20681", "CVE-2024-20680", "CVE-2024-20664", "CVE-2024-20663",
                "CVE-2024-20661", "CVE-2024-20657", "CVE-2024-20654");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-19 16:09:33 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-14 22:37:00 +0000 (Sun, 14 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-10 11:58:21 +0530 (Wed, 10 Jan 2024)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5034123)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5034123");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Windows Themes Spoofing Vulnerability.

  - Remote Desktop Client Remote Code Execution Vulnerability.

  - Microsoft Common Log File System Elevation of Privilege Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information, bypass security restrictions, spoofing and conduct Denial of
  service attacks on an affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows 11 version 22H2 for x64-based Systems

  - Microsoft Windows 11 Version 23H2 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5034123");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_in_range(version:fileVer, test_version:"10.0.22621.0", test_version2:"10.0.22621.3006")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\Ntoskrnl.exe", file_version:fileVer,
                            vulnerable_range:"10.0.22621.0 - 10.0.22621.3006");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
