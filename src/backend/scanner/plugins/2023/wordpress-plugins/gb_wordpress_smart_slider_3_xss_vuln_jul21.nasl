# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:nextendweb:smart_slider_3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126449");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-01 08:20:45 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-22 20:09:00 +0000 (Tue, 22 Jun 2021)");

  script_cve_id("CVE-2021-24382");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress The Smart Slider 3 Plugin < 3.5.0.9 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/smart-slider-3/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'The Smart Slider 3' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin did not sanitise the Project Name before outputting
  it back in the page, leading to a Stored Cross-Site Scripting issue. By default, only
  administrator users could access the affected functionality, limiting the exploitability of the
  vulnerability.");

  script_tag(name:"affected", value:"WordPress Smart Slider 3 prior to version 3.5.0.9.");

  script_tag(name:"solution", value:"Update to version 3.5.0.9 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/7b32a282-e51f-4ee5-b59f-5ba10e62a54d");

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

if (version_is_less(version: version, test_version: "3.5.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
