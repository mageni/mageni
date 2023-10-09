# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832356");
  script_version("2023-08-24T05:06:01+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-26789", "CVE-2022-26786", "CVE-2022-26916", "CVE-2022-26802",
                "CVE-2022-26917", "CVE-2022-26809", "CVE-2022-26808", "CVE-2022-26807",
                "CVE-2022-26795", "CVE-2022-26792", "CVE-2022-26794", "CVE-2022-26904",
                "CVE-2022-26803", "CVE-2022-26919", "CVE-2022-26830", "CVE-2022-26797",
                "CVE-2022-26787", "CVE-2022-24549", "CVE-2022-26914", "CVE-2022-26801",
                "CVE-2022-26798", "CVE-2022-26793", "CVE-2022-26918", "CVE-2022-26826",
                "CVE-2022-26796", "CVE-2022-26831", "CVE-2022-26790", "CVE-2022-26920",
                "CVE-2022-26915", "CVE-2022-26788", "CVE-2022-24545", "CVE-2022-24496",
                "CVE-2022-24544", "CVE-2022-24493", "CVE-2022-24541", "CVE-2022-24492",
                "CVE-2022-24540", "CVE-2022-24491", "CVE-2022-24537", "CVE-2022-24488",
                "CVE-2022-24487", "CVE-2022-24486", "CVE-2022-24534", "CVE-2022-24485",
                "CVE-2022-24533", "CVE-2022-24481", "CVE-2022-24479", "CVE-2022-24474",
                "CVE-2022-24521", "CVE-2022-23268", "CVE-2022-24550", "CVE-2022-24499",
                "CVE-2022-24547", "CVE-2022-24498", "CVE-2022-24546", "CVE-2022-24495",
                "CVE-2022-24494", "CVE-2022-24542", "CVE-2022-24483", "CVE-2022-24528",
                "CVE-2022-23257", "CVE-2022-21983", "CVE-2022-22009", "CVE-2022-22008",
                "CVE-2022-24500", "CVE-2022-24530", "CVE-2022-24497", "CVE-2022-24482");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-24 05:06:01 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-19 18:37:00 +0000 (Tue, 19 Apr 2022)");
  script_tag(name:"creation_date", value:"2023-08-08 12:00:40 +0530 (Tue, 08 Aug 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5012592)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5012592");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows Fax Compose Form Remote Code Execution Vulnerability.

  - Remote Procedure Call Runtime Remote Code Execution Vulnerability.

  - Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation would allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information and conduct DoS attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 11 version 21H2 for x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5012592");
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

if(version_is_less(version:fileVer, test_version:"10.0.22000.613")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\user32.dll", file_version:fileVer, vulnerable_range:"Less than 10.0.22000.613");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);