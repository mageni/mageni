# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126020");
  script_version("2023-03-27T10:09:49+0000");
  script_tag(name:"last_modification", value:"2023-03-27 10:09:49 +0000 (Mon, 27 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-24 10:31:42 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2023-28334");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 4.0 < 4.0.7, 4.1 < 4.1.2 IDOR Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to an IDOR (Insecure Direct Object Reference)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Authenticated users were able to enumerate other users' names
  via the learning plans page.");

  script_tag(name:"affected", value:"Moodle versions 4.0 prior to 4.0.7, 4.1 prior to 4.1.2.");

  script_tag(name:"solution", value:"Update to version 4.0.7, 4.1.2 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=445066");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.7");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.1", test_version_up: "4.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
