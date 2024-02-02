# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832590");
  script_version("2023-11-23T05:06:17+0000");
  script_cve_id("CVE-2023-36037", "CVE-2023-36041");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-23 05:06:17 +0000 (Thu, 23 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-20 19:52:00 +0000 (Mon, 20 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-16 12:12:23 +0530 (Thu, 16 Nov 2023)");
  script_name("Microsoft Office 2016 Multiple Vulnerabilities (KB5002518)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002518");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Microsoft Excel Remote Code Execution Vulnerability.

  - Microsoft Excel Security Feature Bypass Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and bypass security restrictions on an affected
  system.");

  script_tag(name:"affected", value:"Microsoft Office 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011627");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102372");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(!excelVer) {
  exit(0);
}

excelPath = get_kb_item("SMB/Office/Excel/Install/Path");
if(!excelPath) {
  excelPath = "Unable to fetch the install path";
}

if(excelVer =~ "^16\." && version_is_less(version:excelVer, test_version:"16.0.5422.1000")) {
  report = report_fixed_ver(file_checked:excelPath + "Excel.exe", file_version:excelVer, vulnerable_range:"16.0 - 16.0.5422.0999");
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
