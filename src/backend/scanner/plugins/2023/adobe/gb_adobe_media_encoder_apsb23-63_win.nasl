# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:media_encoder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832702");
  script_version("2023-12-01T16:11:30+0000");
  script_cve_id("CVE-2023-47040", "CVE-2023-47041", "CVE-2023-47042", "CVE-2023-47043",
                "CVE-2023-47044");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-22 15:18:00 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-17 12:31:15 +0530 (Fri, 17 Nov 2023)");
  script_name("Adobe Media Encoder Security Update (APSB23-63) - Windows");

  script_tag(name:"summary", value:"Adobe Media Encoder is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple out-of-bounds read errors.

  - A Heap-based Buffer Overflow error.

  - An Access of Uninitialized Pointer.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and memory leak on an affected system.");

  script_tag(name:"affected", value:"Adobe Media Encoder 23.6 and earlier
  and 24.0.2 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Update to version 23.6.2 or 24.0.3 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/media-encoder/apsb23-63.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_media_encoder_detect_win.nasl");
  script_mandatory_keys("adobe/mediaencoder/win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos["version"];
path = infos["location"];

if (version_is_less(version: vers, test_version: "23.6.2")) {
  fix = "23.6.2";
}

if (version_in_range(version: vers, test_version: "24.0", test_version2: "24.0.2")) {
  fix = "24.0.3";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
