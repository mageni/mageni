# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:machothemes:strong_testimonials";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124502");
  script_version("2024-01-16T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-01-16 05:05:27 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-09 09:45:45 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-11 14:28:00 +0000 (Thu, 11 Jan 2024)");

  script_cve_id("CVE-2023-52123");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Strong Testmionials Plugin < 3.1.11 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/strong-testimonials/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Strong Testmionials' is prone to a
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin allows a malicious actor to force higher privileged
  users to execute unwanted actions under their current authentication.");

  script_tag(name:"affected", value:"WordPress Strong Testmionials prior to version 3.1.11.");

  script_tag(name:"solution", value:"Update to version 3.1.11 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/strong-testimonials/wordpress-strong-testimonials-plugin-3-1-10-cross-site-request-forgery-csrf-vulnerability");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.1.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
