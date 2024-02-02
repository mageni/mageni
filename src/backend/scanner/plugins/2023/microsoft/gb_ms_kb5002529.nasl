# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832635");
  script_version("2023-12-14T08:20:35+0000");
  script_cve_id("CVE-2023-35636");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-14 08:20:35 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 18:58:00 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-13 11:16:35 +0530 (Wed, 13 Dec 2023)");
  script_name("Microsoft Outlook 2016 Information Disclosure Vulnerability (KB5002529)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002529");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an information disclosure
  vulnerability in Microsoft Outlook software.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to disclose sensitive information on an affected system.");

  script_tag(name:"affected", value:"Microsoft Outlook 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002529");
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
if(!outlookVer|| outlookVer !~ "^16\.") {
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

if(version_in_range(version:outlookVer, test_version:"16.0", test_version2:"16.0.5426.0999")) {
  report = report_fixed_ver(file_checked: outlookFile + "outlook.exe",
                            file_version:outlookVer, vulnerable_range:"16.0 - 16.0.5426.0999");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
