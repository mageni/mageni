# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:incsub:forminator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124479");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-21 07:31:23 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-30 14:52:00 +0000 (Thu, 30 Nov 2023)");

  script_cve_id("CVE-2023-6133");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Forminator Plugin < 1.28.0 Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/forminator/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Forminator' is prone to an arbitrary file
  upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This makes it possible for authenticated attackers with
  administrator-level capabilities or above to upload arbitrary files on the affected site's
  server, but due to the htaccess configuration, remote code cannot be executed.");

  script_tag(name:"affected", value:"WordPress Forminator plugin prior to version 1.28.0.");

  script_tag(name:"solution", value:"Update to version 1.28.0 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/13cfa202-ab90-46c0-ab53-00995bfdcaa3");

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

if (version_is_less(version: version, test_version: "1.28.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.28.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
