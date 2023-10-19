# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpwhitesecurity:wp_activity_log";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126427");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 08:08:03 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-16 03:11:00 +0000 (Fri, 16 Jun 2023)");

  script_cve_id("CVE-2023-2261", "CVE-2023-2284", "CVE-2023-2285", "CVE-2023-2286");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Activity Log Plugin < 4.5.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-security-audit-log/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Activity Log' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-2261: Missing capabilities check to user enumeration.

  - CVE-2023-2284: Missing Authorization via ajax_switch_db.

  - CVE-2023-2285: Cross-Site Request Forgery via ajax_switch_db

  - CVE-2023-2286: Cross-Site Request Forgery via ajax_run_cleanup");

  script_tag(name:"affected", value:"WordPress WP Activity Log plugin prior to version 4.5.2.");

  script_tag(name:"solution", value:"Update to version 4.5.2 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/detail/wp-activity-log-450-missing-capabilities-check-to-user-enumeration");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-security-audit-log-premium/wp-activity-log-premium-450-missing-authorization-via-ajax-switch-db");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-security-audit-log-premium/wp-activity-log-premium-450-cross-site-request-forgery-via-ajax-switch-db");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/detail/wp-activity-log-450-cross-site-request-forgery-via-ajax-run-cleanup");

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

if (version_is_less(version: version, test_version: "4.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
