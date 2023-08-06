# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832332");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2023-21729", "CVE-2023-28302", "CVE-2023-28298", "CVE-2023-28293",
                "CVE-2023-28276", "CVE-2023-28253", "CVE-2023-28275", "CVE-2023-28252",
                "CVE-2023-28274", "CVE-2023-28273", "CVE-2023-28250", "CVE-2023-28249",
                "CVE-2023-28272", "CVE-2023-28271", "CVE-2023-28248", "CVE-2023-28270",
                "CVE-2023-28246", "CVE-2023-28269", "CVE-2023-28267", "CVE-2023-28266",
                "CVE-2023-28243", "CVE-2023-28241", "CVE-2023-28236", "CVE-2023-28238",
                "CVE-2023-28237", "CVE-2023-28234", "CVE-2023-28233", "CVE-2023-28232",
                "CVE-2023-28229", "CVE-2023-28228", "CVE-2023-28227", "CVE-2023-28226",
                "CVE-2023-28225", "CVE-2023-28224", "CVE-2023-28222", "CVE-2023-28221",
                "CVE-2023-28220", "CVE-2023-28219", "CVE-2023-28218", "CVE-2023-28217",
                "CVE-2023-28216", "CVE-2023-24931", "CVE-2023-24929", "CVE-2023-24887",
                "CVE-2023-24928", "CVE-2023-24886", "CVE-2023-24927", "CVE-2023-24885",
                "CVE-2023-24926", "CVE-2023-24884", "CVE-2023-24925", "CVE-2023-24883",
                "CVE-2023-24924", "CVE-2023-24914", "CVE-2023-24912", "CVE-2023-21769",
                "CVE-2023-21727", "CVE-2023-21554");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-21 15:44:43 +0530 (Fri, 21 Jul 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5025239)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5025239");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Microsoft WDAC OLE DB provider for SQL Server Remote Execution Vulnerability.

  - Microsoft PostScript and PCL6 Class Printer Driver Remote Code Execution Vulnerability.

  - Windows Internet Key Exchange (IKE) Protocol Extensions Remote Code Execution Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation would allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information and conduct DoS attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 11 version 22H2 for x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5025239");
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

if(version_in_range(version:fileVer, test_version:"10.0.22621.0", test_version2:"10.0.22621.1484")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\user32.dll", file_version:fileVer, vulnerable_range:"10.0.22621.0 - 10.0.22621.1484");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);