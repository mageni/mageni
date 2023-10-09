# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodebb:nodebb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126499");
  script_version("2023-10-03T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-10-03 05:05:26 +0000 (Tue, 03 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-28 09:36:00 +0000 (Thu, 28 Sep 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2023-2850");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NodeBB 2.x < 2.8.13, 3.x < 3.1.3 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_nodebb_detect.nasl");
  script_mandatory_keys("NodeBB/installed");

  script_tag(name:"summary", value:"NodeBB is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Private messages or posts might be leaked to third parties if
  victim opens the attackers site while browsing nodebb.");

  script_tag(name:"affected", value:"NodeBB version 2.x prior to 2.8.13 and 3.x prior to 3.1.3.");

  script_tag(name:"solution", value:"Update to version 2.8.13, 3.1.3 or later.");

  script_xref(name:"URL", value:"https://github.com/NodeBB/NodeBB/security/advisories/GHSA-4qcv-qf38-5j3j");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2.0.0", test_version_up: "2.8.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.0.0", test_version_up: "3.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
