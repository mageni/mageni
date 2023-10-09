# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832352");
  script_version("2023-08-24T05:06:01+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-41345", "CVE-2021-36953", "CVE-2021-36970", "CVE-2021-41357",
                "CVE-2021-40455", "CVE-2021-41347", "CVE-2021-41343", "CVE-2021-41342",
                "CVE-2021-41340", "CVE-2021-41339", "CVE-2021-41338", "CVE-2021-41336",
                "CVE-2021-41334", "CVE-2021-41332", "CVE-2021-26442", "CVE-2021-26441",
                "CVE-2021-40489", "CVE-2021-40488", "CVE-2021-40478", "CVE-2021-40477",
                "CVE-2021-40476", "CVE-2021-40475", "CVE-2021-40470", "CVE-2021-40468",
                "CVE-2021-40467", "CVE-2021-40466", "CVE-2021-40465", "CVE-2021-40464",
                "CVE-2021-40462", "CVE-2021-40463", "CVE-2021-40461", "CVE-2021-40460",
                "CVE-2021-40449", "CVE-2021-40450", "CVE-2021-40454", "CVE-2021-40443",
                "CVE-2021-38672", "CVE-2021-38663", "CVE-2021-38662");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-24 05:06:01 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-19 17:28:00 +0000 (Tue, 19 Oct 2021)");
  script_tag(name:"creation_date", value:"2023-08-07 16:28:22 +0530 (Mon, 07 Aug 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5006674)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5006674");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows MSHTML Platform Remote Code Execution Vulnerability.

  - Windows Graphics Component Remote Code Execution Vulnerability.

  - Windows Media Foundation Dolby Digital Atmos Decoders Remote Code Execution Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation would allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information and conduct DoS attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 11 version 21H2 for x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5006674");
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

if(version_is_less(version:fileVer, test_version:"10.0.22000.194")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\user32.dll", file_version:fileVer, vulnerable_range:"Less than 10.0.22000.194");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);