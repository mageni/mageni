# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832047");
  script_version("2023-04-20T12:00:18+0000");
  script_cve_id("CVE-2023-21954");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-20 12:00:18 +0000 (Thu, 20 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-20 11:57:59 +0530 (Thu, 20 Apr 2023)");
  script_name("Oracle Java SE Security Update (apr2023) 02 - Linux");

  script_tag(name:"summary", value:"Oracle Java SE is prone to remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to improper application of networking protocols
  within the Java SE engine component in Oracle Java SE.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to manipulate data.");

  script_tag(name:"affected", value:"Oracle Java SE version 8u361 and earlier,
  11.0.18, 17.0.6 and earlier on Linux.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2023.html#AppendixJAVA");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.361") ||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.18") ||
   version_in_range(version:vers, test_version:"17.0", test_version2:"17.0.6"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version: "Apply patch from vendor", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
