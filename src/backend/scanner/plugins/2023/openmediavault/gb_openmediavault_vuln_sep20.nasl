# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openmediavault:openmediavault";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102069");
  script_version("2023-09-28T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-09-28 05:05:04 +0000 (Thu, 28 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-25 08:27:17 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-25 18:15:00 +0000 (Wed, 25 Nov 2020)");

  script_cve_id("CVE-2020-26124");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Openmediavault < 3.0.100, 4.x < 4.1.36, 5.x < 5.5.12 PHP Code Injection Vulnerability.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openmediavault_ssh_detect.nasl");
  script_mandatory_keys("openmediavault/detected");

  script_tag(name:"summary", value:"Openmediavault is prone to a PHP code injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Openmediavault allows authenticated PHP code injection attacks,
  via the sortfield POST parameter of rpc.php, because json_encode_safe is not used in
  config/databasebackend.inc.");

  script_tag(name:"impact", value:"Successful exploitation allows arbitrary command execution on the
  underlying operating system as root.");

  script_tag(name:"affected", value:"Openmediavault before 3.0.100, 4.x before 4.1.36 and 5.x before
  5.5.12.");

  script_tag(name:"solution", value:"Update to version 3.0.100 or later for 3.x, 4.1.36 or later for
  4.x and 5.5.12 or later for 5.x.");

  script_xref(name:"URL", value:"https://www.openmediavault.org/?p=2797");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"3.0.100")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.0.100", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

if(version_in_range_exclusive(version:vers, test_version_lo:"4.0", test_version_up:"4.1.36")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.1.36", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

if(version_in_range_exclusive(version:vers, test_version_lo:"5.0", test_version_up:"5.5.12")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.5.12", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
