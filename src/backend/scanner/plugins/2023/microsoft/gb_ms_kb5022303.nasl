# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832334");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2023-21760", "CVE-2023-21758", "CVE-2023-21776", "CVE-2023-21773",
                "CVE-2023-21752", "CVE-2023-21747", "CVE-2023-21767", "CVE-2023-21766",
                "CVE-2023-21527", "CVE-2023-21768", "CVE-2023-21755", "CVE-2023-21754",
                "CVE-2023-21524", "CVE-2023-21771", "CVE-2023-21759", "CVE-2023-21757",
                "CVE-2023-21749", "CVE-2023-21525", "CVE-2023-21774", "CVE-2023-21750",
                "CVE-2023-21772", "CVE-2023-21765", "CVE-2023-21748", "CVE-2023-21746",
                "CVE-2023-21733", "CVE-2023-21739", "CVE-2023-21732", "CVE-2023-21730",
                "CVE-2023-21728", "CVE-2023-21726", "CVE-2023-21724", "CVE-2023-21683",
                "CVE-2023-21682", "CVE-2023-21681", "CVE-2023-21680", "CVE-2023-21679",
                "CVE-2023-21678", "CVE-2023-21677", "CVE-2023-21676", "CVE-2023-21675",
                "CVE-2023-21674", "CVE-2023-21563", "CVE-2023-21561", "CVE-2023-21560",
                "CVE-2023-21559", "CVE-2023-21558", "CVE-2023-21557", "CVE-2023-21556",
                "CVE-2023-21555", "CVE-2023-21552", "CVE-2023-21551", "CVE-2023-21550",
                "CVE-2023-21549", "CVE-2023-21548", "CVE-2023-21543", "CVE-2023-21541",
                "CVE-2023-21540", "CVE-2023-21539", "CVE-2023-21547", "CVE-2023-21546",
                "CVE-2023-21537", "CVE-2023-21536", "CVE-2023-21535", "CVE-2023-21532");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-21 15:44:43 +0530 (Fri, 21 Jul 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5022303)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5022303");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows Layer 2 Tunneling Protocol (L2TP) Remote Execution Vulnerability.

  - Windows Secure Socket Tunneling Protocol (SSTP) Remote Code Execution Vulnerability.

  - Windows Bluetooth Service Remote Code Execution Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation would allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information and conduct DoS attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 11 version 22H2 for x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5022303");
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

if(version_in_range(version:fileVer, test_version:"10.0.22621.0", test_version2:"10.0.22621.1104")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\user32.dll", file_version:fileVer, vulnerable_range:"10.0.22621.0 - 10.0.22621.1104");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);