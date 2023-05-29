# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teampass:teampass";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126342");
  script_version("2023-05-26T16:08:11+0000");
  script_tag(name:"last_modification", value:"2023-05-26 16:08:11 +0000 (Fri, 26 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-25 10:20:24 +0000 (Thu, 25 May 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:N");

  script_cve_id("CVE-2023-2859");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TeamPass < 3.0.9 Code Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_teampass_http_detect.nasl");
  script_mandatory_keys("teampass/detected");

  script_tag(name:"summary", value:"TeamPass is prone to a code injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Stored HTML injection in folderName affecting Admin.");

  script_tag(name:"affected", value:"TeamPass prior to version 3.0.9.");

  script_tag(name:"solution", value:"Update to version 3.0.9 or later."); #NOTE: detection fails in versions 3.0.0 and higher

  script_xref(name:"URL", value:"https://huntr.dev/bounties/d7b8ea75-c74a-4721-89bb-12e5c80fb0ba/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "3.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.9", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
