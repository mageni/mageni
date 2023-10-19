# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webfactoryltd:under_construction";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126431");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-13 10:08:03 +0000 (Thu, 13 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-14 17:52:00 +0000 (Wed, 14 Jun 2023)");

  script_cve_id("CVE-2023-0831", "CVE-2023-0832");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Under Construction Plugin < 3.97 Multiple CSRF Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/under-construction-page/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Under Construction' is prone to multiple
  cross-site request forgery (CSRF) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-0831: Cross-Site Request Forgery via admin_action_ucp_dismiss_notice

  - CVE-2023-0832: Cross-Site Request Forgery via admin_action_install_weglot");

  script_tag(name:"affected", value:"WordPress Under Construction plugin prior to version 3.97.");

  script_tag(name:"solution", value:"Update to version 3.97 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/under-construction-page/under-construction-396-cross-site-request-forgery-via-admin-action-ucp-dismiss-notice");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/under-construction-page/under-construction-396-cross-site-request-forgery-via-admin-action-install-weglot");

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

if (version_is_less(version: version, test_version: "3.97")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.97", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
