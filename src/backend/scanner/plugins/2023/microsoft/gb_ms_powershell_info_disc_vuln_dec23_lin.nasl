# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:powershell";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832640");
  script_version("2023-12-14T08:20:35+0000");
  script_cve_id("CVE-2023-36013");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-14 08:20:35 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-01 17:55:00 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-13 11:16:35 +0530 (Wed, 13 Dec 2023)");
  script_name("Microsoft PowerShell Information Disclosure Vulnerability - Dec 2023 (Linux)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for PowerShell Core according to Microsoft security advisory
  CVE-2023-36013.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists when PowerShell Web cmdlets
  disclose authentication information in an error output in an error case.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose sensitive information on an affected system.");

  script_tag(name:"affected", value:"PowerShell Core versions 7.2 prior to 7.2.17,
  7.3 prior to 7.3.10, 7.4 prior to 7.4.0 on Linux.");

  script_tag(name:"solution", value:"Update to version 7.2.17 or 7.3.10 or 7.4.0
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://github.com/PowerShell/Announcements/issues/55");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36013");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_powershell_core_detect_lin.nasl");
  script_mandatory_keys("PowerShell/Linux/Ver");
  exit(0);
}
include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos["version"];
path = infos["location"];

if(vers =~ "^7\.2" && version_is_less(version:vers, test_version:"7.2.17")) {
  fix = "7.2.17";
}
else if(vers =~ "^7\.3" && version_is_less(version:vers, test_version:"7.3.10")) {
  fix = "7.3.10";
}
#Fix is 7.4.0, 7.4 RC.1 only affected
#pwsh-preview -v = PowerShell 7.4.0-rc.1
else if(vers =~ "^7\.4" && vers == "7.4.0-rc.1") {
  fix = "7.4.0";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
