# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:automatic:woocommerce_payments";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126037");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-24 13:15:00 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-21 15:10:00 +0000 (Fri, 21 Apr 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-28121");

  script_name("WordPress WooCommerce Payments Plugin Authentication Bypass Vulnerability (Mar 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woocommerce-payments/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WooCommerce Payments' is prone to an
  authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Authentication bypass via the
  determine_current_user_for_platform_checkout function.");

  script_tag(name:"affected", value:"WordPress WooCommerce Payments plugin versions 4.8.x prior to
  4.8.2, 4.9.x prior to 4.9.1, 5.0.x prior to 5.0.4, 5.1.x prior to 5.1.3, 5.2.x prior to 5.2.2,
  5.3.x prior to 5.3.1, 5.4.x prior to 5.4.1, 5.5.x prior to 5.5.2 and 5.6.x prior to 5.6.2.");

  script_tag(name:"solution", value:"Update to version 4.8.2, 4.9.1, 5.0.4, 5.1.3, 5.2.2, 5.3.1,
  5.4.1, 5.5.2, 5.6.2 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2023/07/massive-targeted-exploit-campaign-against-woocommerce-payments-underway/");
  script_xref(name:"URL", value:"https://www.rcesecurity.com/2023/07/patch-diffing-cve-2023-28121-to-compromise-a-woocommerce/");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/woocommerce-payments/woocommerce-payments-561-authentication-bypass-and-privilege-escalation");
  script_xref(name:"URL", value:"https://developer.woocommerce.com/2023/03/23/critical-vulnerability-detected-in-woocommerce-payments-what-you-need-to-know/");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2023/03/psa-update-now-critical-authentication-bypass-in-woocommerce-payments-allows-site-takeover/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.8", test_version_up: "4.8.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.9", test_version_up: "4.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "5.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2", test_version_up: "5.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.3", test_version_up: "5.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.4", test_version_up: "5.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5", test_version_up: "5.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6", test_version_up: "5.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
