# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:std42:elfinder";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.149853");
  script_version("2023-06-28T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:22 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-27 03:21:44 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:N");

  script_cve_id("CVE-2023-35840");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("elFinder < 2.1.62 Path Traversal Vulnerability (GHSA-wm5g-p99q-66g4)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elfinder_detect.nasl");
  script_mandatory_keys("studio42/elfinder/detected");

  script_tag(name:"summary", value:"elFinder is prone to a path traversal vulnerability in the PHP
  LocalVolumeDriver connector.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This issue is caused by incomplete validity checking of the
  supplied request parameters.");

  script_tag(name:"impact", value:"This vulnerability can be exploited by allowing untrusted users
  to write to the local file system.");

  script_tag(name:"affected", value:"elFinder version 2.1.61 and prior.");

  script_tag(name:"solution", value:"Update to version 2.1.62 or later.");

  script_xref(name:"URL", value:"https://github.com/Studio-42/elFinder/security/advisories/GHSA-wm5g-p99q-66g4");
  script_xref(name:"URL", value:"https://github.com/afine-com/CVE-2023-35840");

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

if (version_is_less(version: version, test_version: "2.1.62")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.62", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
