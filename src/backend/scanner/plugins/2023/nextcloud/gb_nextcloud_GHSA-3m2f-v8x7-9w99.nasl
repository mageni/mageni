# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149551");
  script_version("2023-04-19T10:08:55+0000");
  script_tag(name:"last_modification", value:"2023-04-19 10:08:55 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-19 08:14:25 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-30539");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server Access Control Vulnerability (GHSA-3m2f-v8x7-9w99)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Depending on the set up tags and other workflows this issue can
  be used to limit access of others or being able to grant them access when there are system tag
  based files access control or files retention rules.");

  script_tag(name:"affected", value:"Nextcloud Server version 24.x prior to 24.0.11 and 25.x prior
  to 25.0.5.");

  script_tag(name:"solution", value:"Update to version 24.0.11, 25.0.5 or later. See the referenced
  vendor advisory for further recommended solutions.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-3m2f-v8x7-9w99");

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

if (version_in_range_exclusive(version: version, test_version_lo: "24.0", test_version_up: "24.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "24.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "25.0", test_version_up: "25.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "25.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
