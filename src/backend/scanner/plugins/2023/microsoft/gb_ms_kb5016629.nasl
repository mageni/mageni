# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832359");
  script_version("2023-08-24T05:06:01+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-35822", "CVE-2022-34711", "CVE-2022-35766", "CVE-2022-35754",
                "CVE-2022-35797", "CVE-2022-35771", "CVE-2022-35804", "CVE-2022-34703",
                "CVE-2022-35794", "CVE-2022-35768", "CVE-2022-33670", "CVE-2022-35767",
                "CVE-2022-35820", "CVE-2022-35757", "CVE-2022-35760", "CVE-2022-35795",
                "CVE-2022-35769", "CVE-2022-35793", "CVE-2022-35761", "CVE-2022-35759",
                "CVE-2022-35758", "CVE-2022-35756", "CVE-2022-35755", "CVE-2022-35753",
                "CVE-2022-35752", "CVE-2022-35751", "CVE-2022-35750", "CVE-2022-35749",
                "CVE-2022-35747", "CVE-2022-35746", "CVE-2022-35745", "CVE-2022-35744",
                "CVE-2022-35743", "CVE-2022-34714", "CVE-2022-34713", "CVE-2022-34712",
                "CVE-2022-34710", "CVE-2022-34709", "CVE-2022-34708", "CVE-2022-34707",
                "CVE-2022-34706", "CVE-2022-34705", "CVE-2022-34704", "CVE-2022-34702",
                "CVE-2022-34701", "CVE-2022-34699", "CVE-2022-34696", "CVE-2022-34691",
                "CVE-2022-34690", "CVE-2022-34302", "CVE-2022-30194", "CVE-2022-30144",
                "CVE-2022-30133", "CVE-2022-30197", "CVE-2022-34301", "CVE-2022-34303");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-24 05:06:01 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-08 12:00:40 +0530 (Tue, 08 Aug 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5016629)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5016629");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows Secure Socket Tunneling Protocol (SSTP) Remote Code Execution Vulnerability.

  - SMB Client and Server Remote Code Execution Vulnerability.

  - Windows Kernel Remote Code Execution Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation would allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information and conduct DoS attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 11 version 21H2 for x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5016629");
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

if(version_is_less(version:fileVer, test_version:"10.0.22000.832")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\user32.dll", file_version:fileVer, vulnerable_range:"Less than 10.0.22000.832");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);