# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832357");
  script_version("2023-08-24T05:06:01+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-30190", "CVE-2022-30138", "CVE-2022-29132", "CVE-2022-29133",
                "CVE-2022-29140", "CVE-2022-29139", "CVE-2022-29131", "CVE-2022-22019",
                "CVE-2022-29141", "CVE-2022-29129", "CVE-2022-29137", "CVE-2022-29130",
                "CVE-2022-29128", "CVE-2022-29127", "CVE-2022-29126", "CVE-2022-29125",
                "CVE-2022-29121", "CVE-2022-29116", "CVE-2022-29115", "CVE-2022-29114",
                "CVE-2022-29113", "CVE-2022-29112", "CVE-2022-29104", "CVE-2022-29103",
                "CVE-2022-22017", "CVE-2022-22016", "CVE-2022-22015", "CVE-2022-22014",
                "CVE-2022-22013", "CVE-2022-22012", "CVE-2022-26940", "CVE-2022-26936",
                "CVE-2022-26935", "CVE-2022-26934", "CVE-2022-26933", "CVE-2022-26930",
                "CVE-2022-26927", "CVE-2022-26926", "CVE-2022-26925", "CVE-2022-26913",
                "CVE-2022-24466", "CVE-2022-26931", "CVE-2022-23279", "CVE-2022-23270",
                "CVE-2022-21972");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-24 05:06:01 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-02 14:00:00 +0000 (Thu, 02 Jun 2022)");
  script_tag(name:"creation_date", value:"2023-08-08 12:00:40 +0530 (Tue, 08 Aug 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5013943)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5013943");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

  - Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability.

  - Remote Procedure Call Runtime Remote Code Execution Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation would allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information and conduct DoS attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 11 version 21H2 for x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5013943");
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
if(!build) {
  exit(0);
}

dllPath = smb_get_systemroot();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"\system32\user32.dll");
if(!fileVer) {
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"10.0.22000.675")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\user32.dll", file_version:fileVer, vulnerable_range:"Less than 10.0.22000.675");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);