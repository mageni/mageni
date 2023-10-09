# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832362");
  script_version("2023-08-24T05:06:01+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-22035", "CVE-2022-30198", "CVE-2022-37997", "CVE-2022-38046",
                "CVE-2022-37995", "CVE-2022-38021", "CVE-2022-37984", "CVE-2022-38043",
                "CVE-2022-24504", "CVE-2022-38022", "CVE-2022-33634", "CVE-2022-38041",
                "CVE-2022-38026", "CVE-2022-37994", "CVE-2022-37985", "CVE-2022-38040",
                "CVE-2022-38042", "CVE-2022-38045", "CVE-2022-38028", "CVE-2022-35770",
                "CVE-2022-37975", "CVE-2022-37986", "CVE-2022-37987", "CVE-2022-37965",
                "CVE-2022-33645", "CVE-2022-33635", "CVE-2022-37993", "CVE-2022-37991",
                "CVE-2022-37990", "CVE-2022-38038", "CVE-2022-37989", "CVE-2022-38037",
                "CVE-2022-37988", "CVE-2022-38033", "CVE-2022-38032", "CVE-2022-38031",
                "CVE-2022-37982", "CVE-2022-38029", "CVE-2022-37977", "CVE-2022-38034",
                "CVE-2022-38036", "CVE-2022-37978", "CVE-2022-38025", "CVE-2022-37974",
                "CVE-2022-37973", "CVE-2022-37998", "CVE-2022-37980", "CVE-2022-37970",
                "CVE-2022-37983", "CVE-2022-38016", "CVE-2022-38030", "CVE-2022-38039",
                "CVE-2022-37979", "CVE-2022-41081", "CVE-2022-41033", "CVE-2022-37981",
                "CVE-2022-38003", "CVE-2022-38051", "CVE-2022-38050", "CVE-2022-38000",
                "CVE-2022-37996", "CVE-2022-38027", "CVE-2022-38044", "CVE-2022-37999",
                "CVE-2022-38047");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-08-24 05:06:01 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-08 12:00:40 +0530 (Tue, 08 Aug 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5018418)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5018418");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows Point-to-Point Tunneling Protocol Remote Code Execution Vulnerability.

  - Windows Secure Channel Remote Code Execution Vulnerability.

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
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5018418");
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

if(version_is_less(version:fileVer, test_version:"10.0.22000.1098")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\user32.dll", file_version:fileVer, vulnerable_range:"Less than 10.0.22000.1098");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);