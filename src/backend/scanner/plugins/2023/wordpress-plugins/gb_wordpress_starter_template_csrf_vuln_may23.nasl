# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:brainstormforce:starter_templates";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126400");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-02 08:10:27 +0000 (Fri, 02 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-26 18:37:00 +0000 (Fri, 26 May 2023)");

  script_cve_id("CVE-2022-46851");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Starter Templates Plugin < 3.1.21 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/astra-sites/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Starter Templates - Elementor, Gutenberg &
  Beaver Builder Templates' is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Starter Templates - Elementor, Gutenberg & Beaver
  Builder Templates prior to version 3.1.21.");

  script_tag(name:"solution", value:"Update to version 3.1.21 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/astra-sites/wordpress-starter-templates-elementor-wordpress-beaver-builder-templates-plugin-3-1-20-cross-site-request-forgery-csrf");

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

if (version_is_less(version: version, test_version: "3.1.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
