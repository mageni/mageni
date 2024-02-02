# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832703");
  script_version("2023-11-24T16:09:32+0000");
  script_cve_id("CVE-2023-44336", "CVE-2023-44337", "CVE-2023-44338", "CVE-2023-44359",
                "CVE-2023-44365", "CVE-2023-44366", "CVE-2023-44367", "CVE-2023-44371",
                "CVE-2023-44372", "CVE-2023-44339", "CVE-2023-44340", "CVE-2023-44348",
                "CVE-2023-44356", "CVE-2023-44357", "CVE-2023-44358", "CVE-2023-44360",
                "CVE-2023-44361");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-24 16:09:32 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-22 16:58:00 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-17 15:19:01 +0530 (Fri, 17 Nov 2023)");
  script_name("Adobe Acrobat DC Continuous Security Update (APSB23-54) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat DC (Continuous) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple Out-of-bounds Read errors.

  - An Access of Uninitialized Pointer.

  - Multiple Use After Free errors.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and memory leak on an affected system.");

  script_tag(name:"affected", value:"Adobe Acrobat DC (Continuous) versions
  23.006.20360 and earlier on Windows.");

  script_tag(name:"solution", value:"Update to version 23.006.20380 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb23-54.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_cont_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Continuous/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"23.006.20360")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"23.006.20380", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
