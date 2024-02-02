# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:premiere_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832711");
  script_version("2023-11-24T16:09:32+0000");
  script_cve_id("CVE-2023-47055", "CVE-2023-47056", "CVE-2023-47057", "CVE-2023-47058",
                "CVE-2023-47059", "CVE-2023-47060");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-24 16:09:32 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-22 17:21:00 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-17 12:57:36 +0530 (Fri, 17 Nov 2023)");
  script_name("Adobe Premiere Pro Security Update (APSB23-65) - Windows");

  script_tag(name:"summary", value:"Adobe Premiere Pro is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An Use-After-Free error.

  - A Heap-based Buffer Overflow.

  - Multiple Out-of-bounds Read or Write errors.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and memory leak on an affected system.");

  script_tag(name:"affected", value:"Adobe Premiere Pro versions 24.0 prior to 24.0.3
  and prior to 23.6.2.");

  script_tag(name:"solution", value:"Update to version 24.0.3 or 23.6.2 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/premiere_pro/apsb23-65.html");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_premiere_pro_detect_win.nasl");
  script_mandatory_keys("adobe/premierepro/win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_in_range_exclusive(version:vers, test_version_lo:"24.0", test_version_up:"24.0.3")) {
  fix = "24.0.3";
}

if(version_is_less(version:vers, test_version:"23.6.2")) {
  fix = "23.6.2";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
