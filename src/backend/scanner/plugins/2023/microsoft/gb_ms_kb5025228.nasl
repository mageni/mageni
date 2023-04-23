# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832032");
  script_version("2023-04-13T10:09:33+0000");
  script_cve_id("CVE-2023-21729", "CVE-2023-28308", "CVE-2023-28307", "CVE-2023-28306",
                "CVE-2023-28305", "CVE-2023-28302", "CVE-2023-28298", "CVE-2023-28293",
                "CVE-2023-28256", "CVE-2023-28278", "CVE-2023-28255", "CVE-2023-28254",
                "CVE-2023-28253", "CVE-2023-28276", "CVE-2023-28275", "CVE-2023-28252",
                "CVE-2023-28273", "CVE-2023-28250", "CVE-2023-28249", "CVE-2023-28272",
                "CVE-2023-28271", "CVE-2023-28248", "CVE-2023-28247", "CVE-2023-28269",
                "CVE-2023-28268", "CVE-2023-28244", "CVE-2023-28267", "CVE-2023-28266",
                "CVE-2023-28243", "CVE-2023-28241", "CVE-2023-28240", "CVE-2023-28236",
                "CVE-2023-28238", "CVE-2023-28237", "CVE-2023-28232", "CVE-2023-28231",
                "CVE-2023-28228", "CVE-2023-28229", "CVE-2023-28227", "CVE-2023-28226",
                "CVE-2023-28225", "CVE-2023-28224", "CVE-2023-28223", "CVE-2023-28222",
                "CVE-2023-28221", "CVE-2023-28220", "CVE-2023-28219", "CVE-2023-28218",
                "CVE-2023-28217", "CVE-2023-28216", "CVE-2023-24931", "CVE-2023-24929",
                "CVE-2023-24887", "CVE-2023-24928", "CVE-2023-24886", "CVE-2023-24927",
                "CVE-2023-24885", "CVE-2023-24926", "CVE-2023-24884", "CVE-2023-24925",
                "CVE-2023-24883", "CVE-2023-24924", "CVE-2023-24912", "CVE-2023-21769",
                "CVE-2023-21727", "CVE-2023-21554");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-04-13 10:09:33 +0000 (Thu, 13 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-12 10:56:21 +0530 (Wed, 12 Apr 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5025228)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5025228");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A Remote Code Execution Vulnerability in Microsoft PostScript and PCL6 Class Printer Driver.

  - An Information Disclosure vulnerability in Microsoft PostScript and PCL6 Class Printer Driver.

  - A Remote Code Execution Vulnerability in Microsoft Message Queuing.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information, bypass security restrictions.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1607 for 32-bit Systems

  - Microsoft Windows 10 Version 1607 for x64-based Systems

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5025228");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.5849"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.14393.0 - 10.0.14393.5849");
  security_message(data:report);
  exit(0);
}
