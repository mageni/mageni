# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832228");
  script_version("2023-07-14T05:06:08+0000");
  script_cve_id("CVE-2023-33150");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 10:51:38 +0530 (Wed, 12 Jul 2023)");
  script_name("Microsoft Word 2016 Security Feature Bypass Vulnerability (KB5002406)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5002406");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a security feature bypass
  vulnerability in Microsoft Word.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to bypass specific functionality of the Office Protected View.");

  script_tag(name:"affected", value:"Microsoft Word 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002406");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");

vers = get_kb_item("SMB/Office/Word/Version");
if(!vers)
  exit(0);

path = get_kb_item("SMB/Office/Word/Install/Path");
if(!path)
  path = "Unable to fetch the install path";

if(vers =~ "^16\." && version_is_less(version:vers, test_version:"16.0.5404.1000")) {
  report = report_fixed_ver(file_checked:path + "winword.exe",
                            file_version:vers, vulnerable_range:"16.0 - 16.0.5404.0999");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
