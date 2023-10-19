# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:premio:chaty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124368");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-19 07:16:45 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-28 13:22:00 +0000 (Fri, 28 Jul 2023)");

  script_cve_id("CVE-2023-3245");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Chaty Plugin < 3.1.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/chaty/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Chaty' is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise and escape some of its settings,
  which could allow high privilege users such as admin to perform stored cross-site scripting
  attacks even when the unfiltered_html capability is disallowed (for example in multisite setup).");

  script_tag(name:"affected", value:"WordPress Chaty plugin prior to version 3.1.2.");

  script_tag(name:"solution", value:"Update to version 3.1.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/f9f8ae7e-6621-4e29-9257-b8306dbe8811");

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

if (version_is_less(version: version, test_version: "3.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
