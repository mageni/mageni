# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126465");
  script_version("2023-08-25T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-08-25 16:09:51 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-24 08:08:31 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2023-1409");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB Improper Authorization Vulnerability (SERVER-73662) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MongoDB is prone to an improper authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If the MongoDB Server is configured to use TLS with a specific
  set of configuration options, it is possible that client certificate validation may not be in
  effect, potentially allowing client to establish a TLS connection with the server that supplies
  any certificate.");

  script_tag(name:"affected", value:"MongoDB version 4.4 prior to 4.4.23, 5.x prior to 5.0.19,
  6.x prior to 6.0.7 and 6.3 prior to 7.0.0-rc2.");

  script_tag(name:"solution", value:"Update to version 4.4.23, 5.0.19, 6.0.7, 7.0.0-rc2
  or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-73662");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "4.4", test_version_up: "4.4.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.23");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "5.0.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.19");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.7");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.3", test_version_up: "7.0.0-rc2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0-rc2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
