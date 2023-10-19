# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xibodevelopment:backupwordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124296");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-20 07:44:07 +0000 (Mon, 20 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-14 20:02:00 +0000 (Tue, 14 Mar 2023)");

  script_cve_id("CVE-2022-4931");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress BackupWordPress Plugin < 3.13 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/backupwordpress/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'BackupWordPress' is prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This is due to missing authorization on the
  heartbeat_received() function that triggers on WordPress heartbeat. This makes it possible for
  authenticated attackers, with subscriber-level permissions and above to retrieve back-up paths
  that can subsequently be used to download the back-up.");

  script_tag(name:"affected", value:"WordPress BackupWordPress plugin prior to version 3.13.");

  script_tag(name:"solution", value:"Update to version 3.13 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/747c86f4-118b-4a9c-899c-e9067d2c7a02");

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

if (version_is_less_equal(version: version, test_version: "3.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
