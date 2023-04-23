# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832044");
  script_version("2023-04-20T12:00:18+0000");
  script_cve_id("CVE-2023-21990", "CVE-2023-21987", "CVE-2022-42916", "CVE-2023-22002",
                "CVE-2023-21989", "CVE-2023-21998", "CVE-2023-22000", "CVE-2023-22001",
                "CVE-2023-21988", "CVE-2023-21999", "CVE-2023-21991");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-20 12:00:18 +0000 (Thu, 20 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-19 15:44:19 +0530 (Wed, 19 Apr 2023)");
  script_name("Oracle VirtualBox Security Update(apr2023) - Mac OS X");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple errors
  in 'Core' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"VirtualBox versions 6.1.x prior to 6.1.44,
  7.0.x prior to 7.0.8 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version 6.1.44
  or 7.0.8 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2023.html#AppendixOVIR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^6\.1\." && version_is_less(version:vers, test_version:"6.1.44")){
  fix = "6.1.44";
}
else if(vers =~ "^7\.0\." && version_is_less(version:vers, test_version:"7.0.8")){
  fix = "7.0.8";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
