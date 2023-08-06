# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832155");
  script_version("2023-07-25T05:05:58+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-33151", "CVE-2023-35311");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 14:53:27 +0530 (Wed, 12 Jul 2023)");
  script_name("Microsoft Outlook 2013 Service Pack 1 Multiple Vulnerabilities (KB5002432)");

  script_tag(name:"summary", value:"This host is missing an critical security
  update according to Microsoft KB5002432");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaws exist due:

  Microsoft Outlook Spoofing Vulnerability and

  Microsoft Outlook Security Feature Bypass Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker
  to obtain sensitive information.");

  script_tag(name:"affected", value:"Microsoft Outlook 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002432/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Outlook/Version");
  script_require_ports(139, 445);
  exit(0);
}
include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

outlookVer = get_kb_item("SMB/Office/Outlook/Version");
if(!outlookVer|| outlookVer !~ "^15\.") {
  exit(0);
}

outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE", item:"Path");
if(!outlookFile) {
  exit(0);
}

outlookVer = fetch_file_version(sysPath:outlookFile, file_name:"outlook.exe");
if(!outlookVer) {
  exit(0);
}

if(version_in_range(version:outlookVer, test_version:"15.0", test_version2:"15.0.5571.0999")) {
  report = report_fixed_ver(file_checked: outlookFile + "outlook.exe",
                            file_version:outlookVer, vulnerable_range:"15.0 - 15.0.5571.0999");
  security_message(data:report);
  exit(0);
}
