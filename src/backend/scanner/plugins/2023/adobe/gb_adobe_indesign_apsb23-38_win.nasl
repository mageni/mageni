# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832259");
  script_version("2023-08-25T16:09:51+0000");
  script_cve_id("CVE-2023-29308", "CVE-2023-29309", "CVE-2023-29310", "CVE-2023-29311",
                "CVE-2023-29312", "CVE-2023-29313", "CVE-2023-29314", "CVE-2023-29315",
                "CVE-2023-29316", "CVE-2023-29317", "CVE-2023-29318", "CVE-2023-29319");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-25 16:09:51 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-22 15:31:46 +0530 (Tue, 22 Aug 2023)");
  script_name("Adobe InDesign Multiple Vulnerabilities (APSB23-38) - Windows");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe InDesign August 2023 update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to Out-of-bounds Read/Write
  errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to memory leak on the system.");

  script_tag(name:"affected", value:"Adobe InDesign 18.3 and earlier versions,
  17.4.1 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Update to version 18.4 or 17.4.2 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb23-38.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_indesign_detect.nasl");
  script_mandatory_keys("Adobe/InDesign/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_in_range(version: vers, test_version: "17.0", test_version2: "17.4.1")) {
  fix = "17.4.2";
}

if (version_in_range(version: vers, test_version: "18.0", test_version2: "18.3")) {
  fix = "18.4";
}

if(fix)
{
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
