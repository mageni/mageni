# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126540");
  script_version("2023-11-07T05:06:14+0000");
  script_tag(name:"last_modification", value:"2023-11-07 05:06:14 +0000 (Tue, 07 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-31 09:31:42 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-07 16:48:00 +0000 (Fri, 07 Oct 2022)");

  script_cve_id("CVE-2022-2986");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 3.11.x < 3.11.9, 4.0.x < 4.0.3 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to a cross site request forgery (CSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Enabling and disabling installed H5P libraries did not include
  the necessary token to prevent a CSRF risk.");

  script_tag(name:"affected", value:"Moodle version 3.11.x prior to 3.11.9 and 4.0.x prior to
  4.0.3.");

  script_tag(name:"solution", value:"Update to version 3.11.9, 4.0.3 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=437685");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "3.11.0", test_version_up: "3.11.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.0.0", test_version_up: "4.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
