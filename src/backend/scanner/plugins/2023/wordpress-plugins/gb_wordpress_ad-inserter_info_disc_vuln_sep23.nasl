# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ad_inserter_project:ad_inserter";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126515");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-25 19:08:03 +0000 (Wed, 25 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-27 18:46:00 +0000 (Fri, 27 Oct 2023)");

  script_cve_id("CVE-2023-4668");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ad Inserter Plugin < 2.7.31 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ad-inserter/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Ad Inserter' is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Sensitive information exposure via the ai-debug-processing-fe
  URL parameter.");

  script_tag(name:"affected", value:"WordPress Ad Inserter plugin prior to version 2.7.31.");

  script_tag(name:"solution", value:"Update to version 2.7.31 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/ad-inserter/ad-inserter-2730-unauthenticated-sensitive-information-exposure-via-ai-debug-processing-fe");

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

if (version_is_less(version: version, test_version: "2.7.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);