# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:devowl:wordpress_real_cookie_banner";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170296");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-01-25 20:08:24 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-11 17:38:00 +0000 (Fri, 11 Mar 2022)");

  script_cve_id("CVE-2022-0445");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Real Cookie Banner Plugin < 2.14.2 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/real-cookie-banner/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Real Cookie Banner: GDPR (DSGVO) & ePrivacy
  Cookie Consent' is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not have CSRF checks in place when resetting its
  settings, allowing attackers to make a logged in admin reset them via a CSRF attack.");

  script_tag(name:"affected", value:"WordPress plugin Real Cookie Banner prior to version 2.14.2.");

  script_tag(name:"solution", value:"Update to version 2.14.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/d9f28255-0026-4c42-9e67-d17b618c2285");

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

if (version_is_less(version: version, test_version: "2.14.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.14.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
