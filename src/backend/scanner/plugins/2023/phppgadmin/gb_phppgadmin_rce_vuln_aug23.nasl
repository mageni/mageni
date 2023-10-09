# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phppgadmin:phppgadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151047");
  script_version("2023-09-29T05:05:51+0000");
  script_tag(name:"last_modification", value:"2023-09-29 05:05:51 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-27 03:57:02 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-40619");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("phpPgAdmin <= 7.14.4 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phppgadmin_http_detect.nasl");
  script_mandatory_keys("phppgadmin/detected");

  script_tag(name:"summary", value:"phpPgAdmin is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"phpPgAdmin is vulnerable to deserialization of untrusted data
  which may lead to remote code execution because user-controlled data is directly passed to the
  PHP 'unserialize()' function in multiple places. An example is the functionality to manage tables
  in 'tables.php' where the 'ma[]' POST parameter is deserialized.");

  script_tag(name:"affected", value:"phpPgAdmin version 7.14.4 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 27th August, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/dub-flow/vulnerability-research/tree/main/CVE-2023-40619");

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

if (version_is_less_equal(version: version, test_version: "7.14.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
