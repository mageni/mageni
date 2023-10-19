# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ad_inserter_project:ad_inserter";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126408");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-05-16 08:08:03 +0000 (Tue, 16 May 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-23 17:41:00 +0000 (Tue, 23 May 2023)");

  script_cve_id("CVE-2023-1549");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ad Inserter Plugin < 2.7.27 Code Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ad-inserter/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Ad Inserter' is prone to a code
  injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin unserializes user input provided via the settings,
  which could allow high privilege users such as admin to perform PHP Object Injection when a
  suitable gadget is present");

  script_tag(name:"affected", value:"WordPress Ad Inserter plugin prior to version 2.7.27.");

  script_tag(name:"solution", value:"Update to version 2.7.27 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/c94b3a68-673b-44d7-9251-f3590cc5ee9e");

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

if (version_is_less(version: version, test_version: "2.7.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
