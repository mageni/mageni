# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832520");
  script_version("2023-10-13T05:06:09+0000");
  script_cve_id("CVE-2023-26369");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:09 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-13 09:15:00 +0000 (Wed, 13 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-10-11 15:20:13 +0530 (Wed, 11 Oct 2023)");
  script_name("Adobe Acrobat DC Continuous Security Update (APSB23-34) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat DC Continuous is prone to
  an out-of-bounds write vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds write
  vulnerability in Acrobat DC Continuous.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Adobe Acrobat DC (Continuous)
  23.003.20284 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Update Adobe Acrobat DC (Continuous)
  to version 23.006.20320 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb23-34.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_cont_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Continuous/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"23.003.20284")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"23.006.20320", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}
exit(99);
