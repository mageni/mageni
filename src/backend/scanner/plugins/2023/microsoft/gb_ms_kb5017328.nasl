# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832360");
  script_version("2023-10-06T16:09:51+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-35803", "CVE-2022-37958", "CVE-2022-38006", "CVE-2022-38005",
                "CVE-2022-37957", "CVE-2022-38004", "CVE-2022-37956", "CVE-2022-37955",
                "CVE-2022-37954", "CVE-2022-34734", "CVE-2022-34733", "CVE-2022-34732",
                "CVE-2022-34731", "CVE-2022-34730", "CVE-2022-34729", "CVE-2022-34728",
                "CVE-2022-34727", "CVE-2022-34726", "CVE-2022-34725", "CVE-2022-34723",
                "CVE-2022-34722", "CVE-2022-34721", "CVE-2022-34720", "CVE-2022-34719",
                "CVE-2022-34718", "CVE-2022-35841", "CVE-2022-35840", "CVE-2022-35838",
                "CVE-2022-35837", "CVE-2022-35836", "CVE-2022-35835", "CVE-2022-35834",
                "CVE-2022-35833", "CVE-2022-35832", "CVE-2022-35831", "CVE-2022-30200",
                "CVE-2022-30196", "CVE-2022-30170", "CVE-2022-23960", "CVE-2022-37969");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 17:23:00 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"creation_date", value:"2023-08-08 12:00:40 +0530 (Tue, 08 Aug 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5017328)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5017328");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - SPNEGO Extended Negotiation (NEGOEX) Security Mechanism Remote Code Execution Vulnerability.

  - Windows Fax Service Remote Code Execution Vulnerability.

  - Microsoft ODBC Driver Remote Code Execution Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation would allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information and conduct DoS attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 11 version 21H2 for x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5017328");
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

if(version_is_less(version:fileVer, test_version:"10.0.22000.978")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\user32.dll", file_version:fileVer, vulnerable_range:"Less than 10.0.22000.978");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);