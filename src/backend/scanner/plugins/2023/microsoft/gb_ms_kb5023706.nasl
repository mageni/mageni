# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832333");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2023-23392", "CVE-2023-1018", "CVE-2023-24870", "CVE-2023-24872",
                "CVE-2023-23403", "CVE-2023-24909", "CVE-2023-24868", "CVE-2023-24911",
                "CVE-2023-24871", "CVE-2023-24876", "CVE-2023-1017", "CVE-2023-24880",
                "CVE-2023-24910", "CVE-2023-24913", "CVE-2023-24869", "CVE-2023-24908",
                "CVE-2023-24907", "CVE-2023-24867", "CVE-2023-24906", "CVE-2023-24866",
                "CVE-2023-24865", "CVE-2023-24864", "CVE-2023-24863", "CVE-2023-24862",
                "CVE-2023-24861", "CVE-2023-24859", "CVE-2023-24858", "CVE-2023-24857",
                "CVE-2023-24856", "CVE-2023-23423", "CVE-2023-23422", "CVE-2023-23421",
                "CVE-2023-23420", "CVE-2023-23419", "CVE-2023-23418", "CVE-2023-23417",
                "CVE-2023-23416", "CVE-2023-23415", "CVE-2023-23414", "CVE-2023-23413",
                "CVE-2023-23411", "CVE-2023-23410", "CVE-2023-23409", "CVE-2023-23407",
                "CVE-2023-23406", "CVE-2023-23405", "CVE-2023-23404", "CVE-2023-23402",
                "CVE-2023-23401", "CVE-2023-23394", "CVE-2023-23393", "CVE-2023-23388",
                "CVE-2023-23385", "CVE-2023-21708");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-21 15:44:43 +0530 (Fri, 21 Jul 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5023706)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5023706");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - HTTP Protocol Stack Remote Execution Vulnerability.

  - Microsoft PostScript and PCL6 Class Printer Remote Code Execution Vulnerability.

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
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5023706");
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

if(version_in_range(version:fileVer, test_version:"10.0.22621.0", test_version2:"10.0.22621.1412")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\user32.dll", file_version:fileVer, vulnerable_range:"10.0.22621.0 - 10.0.22621.1412");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);