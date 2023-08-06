# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832300");
  script_version("2023-07-25T05:05:58+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-35299", "CVE-2023-32053", "CVE-2023-35366", "CVE-2023-33154",
                "CVE-2023-32044", "CVE-2023-35367", "CVE-2023-32057", "CVE-2023-32055",
                "CVE-2023-33169", "CVE-2023-36874", "CVE-2023-35310", "CVE-2023-32054",
                "CVE-2023-35365", "CVE-2023-32050", "CVE-2023-33168", "CVE-2023-35303",
                "CVE-2023-32038", "CVE-2023-21526", "CVE-2023-35309", "CVE-2023-33174",
                "CVE-2023-35351", "CVE-2023-35350", "CVE-2023-35346", "CVE-2023-35345",
                "CVE-2023-35344", "CVE-2023-35342", "CVE-2023-35341", "CVE-2023-35340",
                "CVE-2023-35338", "CVE-2023-35332", "CVE-2023-35330", "CVE-2023-35328",
                "CVE-2023-35322", "CVE-2023-35321", "CVE-2023-35319", "CVE-2023-35318",
                "CVE-2023-35316", "CVE-2023-35314", "CVE-2023-35312", "CVE-2023-35300",
                "CVE-2023-35297", "CVE-2023-32046", "CVE-2023-32045", "CVE-2023-32043",
                "CVE-2023-32042", "CVE-2023-32035", "CVE-2023-32034", "CVE-2023-32033",
                "CVE-2023-33173", "CVE-2023-33172", "CVE-2023-33167", "CVE-2023-33166",
                "CVE-2023-33164", "CVE-2023-33163");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 13:27:16 +0530 (Wed, 12 Jul 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5028240)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5028240");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A Remote Code Execution Vulnerability in Windows Routing and Remote Access Service (RRAS).

  - A Remote Code Execution Vulnerability in Microsoft Message Queuing.

  - A Remote Code Execution Vulnerability in Windows DNS Server.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information and conduct DoS attacks.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5028240");
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

if(hotfix_check_sp(win2008r2:2) <= 0){
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

if(version_is_less(version:fileVer, test_version:"6.1.7601.26623")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe", file_version:fileVer, vulnerable_range:"Less than 6.1.7601.26623");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);