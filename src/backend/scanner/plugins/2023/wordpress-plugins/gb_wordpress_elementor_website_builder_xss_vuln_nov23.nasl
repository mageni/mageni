# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elementor:website_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126557");
  script_version("2023-12-08T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-12-08 05:05:53 +0000 (Fri, 08 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-06-02 10:52:22 +0000 (Fri, 02 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-05 20:15:00 +0000 (Tue, 05 Dec 2023)");

  script_cve_id("CVE-2023-47505");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Elementor Website Builder Plugin < 3.16.5 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/elementor/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Elementor Website Builder' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper neutralization of input during web page generation,
  leading to a cross-site scripting (XSS).");

  script_tag(name:"affected", value:"WordPress Elementor Website Builder plugin prior to version
  3.16.5.");

  script_tag(name:"solution", value:"Update to version 3.16.5 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/elementor/wordpress-elementor-plugin-3-16-4-cross-site-scripting-xss-vulnerability");

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

if (version_is_less(version: version, test_version: "3.16.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.16.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
