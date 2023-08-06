# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832315");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2023-25193", "CVE-2023-22036", "CVE-2023-22006");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-19 19:35:02 +0530 (Wed, 19 Jul 2023)");
  script_name("Oracle Java SE Security Update (jul2023) 01 - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  errors in the multiple components.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to manipulate data and execute arbitrary code.");

  script_tag(name:"affected", value:"Oracle Java SE version 11.0.19, 17.0.7, 20.0.1 and earlier on Windows.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2023.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:oracle:jre";

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.19") ||
   version_in_range(version:vers, test_version:"17.0", test_version2:"17.0.7") ||
   version_in_range(version:vers, test_version:"20.0", test_version2:"20.0.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version: "Apply patch from vendor", install_path:path);

  security_message(port:0, data:report);
  exit(0);
}

exit(99);
