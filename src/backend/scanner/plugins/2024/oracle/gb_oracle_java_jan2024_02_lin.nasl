# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832792");
  script_version("2024-01-24T05:06:24+0000");
  script_cve_id("CVE-2024-20918", "CVE-2024-20952", "CVE-2024-20919", "CVE-2024-20921",
                "CVE-2024-20945");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-01-24 05:06:24 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 23:12:00 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-17 11:19:29 +0530 (Wed, 17 Jan 2024)");
  script_name("Oracle Java SE Security Update (jan2024) 02 - Linux");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  errors in the multiple components.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to compromise Oracle Java SE, which can result in unauthorized update,
  insert or delete access to critical data or all Oracle Java SE");

  script_tag(name:"affected", value:"Oracle Java SE version 8u391 and earlier
  11.0.21, 17.0.9, 21.0.1 and earlier on Linux.");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2024.html#AppendixJAVA");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Oracle/Java/JDK_or_JRE/Linux/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:oracle:jre";

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.391") ||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.21") ||
   version_in_range(version:vers, test_version:"17.0", test_version2:"17.0.9") ||
   version_in_range(version:vers, test_version:"21.0", test_version2:"21.0.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version: "Apply patch provided by the vendor", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
