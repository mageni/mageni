# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832252");
  script_version("2023-08-25T16:09:51+0000");
  script_cve_id("CVE-2023-38226", "CVE-2023-38227", "CVE-2023-38228", "CVE-2023-38229",
                "CVE-2023-38230", "CVE-2023-38231", "CVE-2023-38232", "CVE-2023-38233",
                "CVE-2023-38234", "CVE-2023-38235", "CVE-2023-38236", "CVE-2023-38237",
                "CVE-2023-38238", "CVE-2023-38239", "CVE-2023-38240", "CVE-2023-38241",
                "CVE-2023-38242", "CVE-2023-38244", "CVE-2023-38222", "CVE-2023-38224",
                "CVE-2023-38225", "CVE-2023-38247", "CVE-2023-38248", "CVE-2023-38243",
                "CVE-2023-38223", "CVE-2023-29303", "CVE-2023-29299", "CVE-2023-29320",
                "CVE-2023-38245", "CVE-2023-38246");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-25 16:09:51 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-22 13:37:45 +0530 (Tue, 22 Aug 2023)");
  script_name("Adobe Acrobat Classic 2020 Security Update (APSB23-30) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper input validation.

  - An improper access control error.

  - Multiple out-of-bounds read or write errors.

  - Violation of secure design principles.

  - Multiple use after free errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to escalate privileges, execute arbitrary code, cause denial of service, bypass
  security restrictions and cause memory leak on an affected system.");

  script_tag(name:"affected", value:"Adobe Acrobat Classic 2020 versions prior to
  20.005.30514.10514 on Windows.");

  script_tag(name:"solution", value:"Update to version 20.005.30514.10514 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb23-30.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Classic/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"20.0", test_version2:"20.005.30467"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"20.005.30514.10514(2020.005.30514.10514)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
