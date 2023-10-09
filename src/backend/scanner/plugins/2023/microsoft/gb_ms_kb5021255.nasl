# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832363");
  script_version("2023-08-18T05:05:27+0000");
  script_cve_id("CVE-2022-41094", "CVE-2022-41076", "CVE-2022-44710", "CVE-2022-44707",
                "CVE-2022-44697", "CVE-2022-44689", "CVE-2022-44683", "CVE-2022-44682",
                "CVE-2022-44681", "CVE-2022-44680", "CVE-2022-44679", "CVE-2022-44677",
                "CVE-2022-44678", "CVE-2022-44676", "CVE-2022-44675", "CVE-2022-44674",
                "CVE-2022-44671", "CVE-2022-44670", "CVE-2022-44669", "CVE-2022-44668",
                "CVE-2022-44667", "CVE-2022-44666", "CVE-2022-41121", "CVE-2022-41077",
                "CVE-2022-41074");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-18 05:05:27 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-08 12:00:40 +0530 (Tue, 08 Aug 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5021255)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5021255");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Microsoft PowerShell Remote Code Execution Vulnerability.

  - Windows Graphics Component Remote Code Execution Vulnerability.

  - Windows Pragmatic General Multicast (PGM) Remote Code Execution Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation would allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information and conduct DoS attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 11 version 22H2 for x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5021255");
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

if(version_in_range(version:fileVer, test_version:"10.0.22621.0", test_version2:"10.0.22621.962")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\user32.dll", file_version:fileVer, vulnerable_range:"10.0.22621.0 - 10.0.22621.962");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);
