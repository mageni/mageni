# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpdeveloper:essential_addons_for_elementor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147608");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2022-02-08 04:00:48 +0000 (Tue, 08 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-04 20:40:00 +0000 (Fri, 04 Feb 2022)");

  script_cve_id("CVE-2022-0320");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Essential Addons for Elementor Plugin < 5.0.5 LFI Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/essential-addons-for-elementor-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Essential Addons for Elementor' is prone
  to a local file inclusion (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The local file inclusion vulnerability exists due to the way
  user input data is used inside of PHP's include function that are part of the ajax_load_more and
  ajax_eael_product_gallery functions.");

  script_tag(name:"affected", value:"WordPress Essential Addons for Elementor plugin prior to
  version 5.0.5.");

  script_tag(name:"solution", value:"Update to version 5.0.5 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/articles/critical-vulnerability-fixed-in-essential-addons-for-elementor-plugin/");

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

if (version_is_less(version: version, test_version: "5.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
