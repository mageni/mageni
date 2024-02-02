# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:seedprod:website_builder_by_seedprod";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126537");
  script_version("2023-11-09T05:05:33+0000");
  script_tag(name:"last_modification", value:"2023-11-09 05:05:33 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-03 08:10:27 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-26 17:27:00 +0000 (Thu, 26 Oct 2023)");

  script_cve_id("CVE-2023-4975");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Website Builder by SeedProd Plugin < 6.15.15.3 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/coming-soon/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Website Builder by SeedProd' is prone to
  a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site request forgery (CSRF) due to missing or incorrect
  nonce validation on functionality in the builder.php file.");

  script_tag(name:"affected", value:"WordPress Website Builder by SeedProd prior to version
  6.15.15.3.");

  script_tag(name:"solution", value:"Update to version 6.15.15.3 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/2cb5370f-14aa-445d-bda3-62a0dd068fc5");

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

if (version_is_less(version: version, test_version: "6.15.15.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.15.15.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
