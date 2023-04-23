# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teampass:teampass";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124305");
  script_version("2023-04-19T10:08:55+0000");
  script_tag(name:"last_modification", value:"2023-04-19 10:08:55 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-17 08:05:24 +0000 (Mon, 17 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:P/A:P");

  script_cve_id("CVE-2023-2021");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TeamPass < 3.0.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_teampass_http_detect.nasl");
  script_mandatory_keys("teampass/detected");

  script_tag(name:"summary", value:"TeamPass is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Stored XSS on function item with folder in nilsteampassnet/teampass");

  script_tag(name:"affected", value:"TeamPass prior to version 3.0.3.");

  script_tag(name:"solution", value:"Update to version 3.0.3 or later."); #NOTE: detection fails in versions 3.0.0 and higher

  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/teampass/commit/77c541a0151841d1f4ceb0a84ca391e1b526d58d");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/2e31082d-7aeb-46ff-84d6-9561758e3bf0");

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

if (version_is_less(version: version, test_version: "3.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
