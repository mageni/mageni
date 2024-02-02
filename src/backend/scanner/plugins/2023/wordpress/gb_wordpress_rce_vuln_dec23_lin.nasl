# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151366");
  script_version("2023-12-12T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-12-12 05:05:39 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-11 03:03:07 +0000 (Mon, 11 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress 6.4.x < 6.4.2 RCE Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"WordPress is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote code execution vulnerability that is not directly
  exploitable in core, however, the WordPress security team feels that there is a potential for
  high severity when combined with some plugins, especially in multisite installations.");

  script_tag(name:"affected", value:"WordPress version 6.4.0 through 6.4.1.");

  script_tag(name:"solution", value:"Update to version 6.4.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/documentation/wordpress-version/version-6-4-2/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "6.4", test_version_up: "6.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
