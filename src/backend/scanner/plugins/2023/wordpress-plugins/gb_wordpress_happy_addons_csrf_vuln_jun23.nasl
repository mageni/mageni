# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wedevs:happy_addons_for_elementor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126443");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-11 07:30:35 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-13 19:16:00 +0000 (Thu, 13 Jul 2023)");

  script_cve_id("CVE-2023-28989");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Happy Addons for Elementor Plugin < 3.8.3 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/happy-elementor-addons/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Happy Addons for Elementor' is prone to a
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site request forgery due to missing nonce validation on
  the handle_optin_optout() function.");

  script_tag(name:"affected", value:"WordPress Happy Addons for Elementor plugin prior to version
  3.8.3.");

  script_tag(name:"solution", value:"Update to version 3.8.3 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/happy-elementor-addons/wordpress-happy-addons-for-elementor-plugin-3-8-2-cross-site-request-forgery-csrf-on-collect-data-popup?_s_id=cve");

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

if (version_is_less(version: version, test_version: "3.8.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
