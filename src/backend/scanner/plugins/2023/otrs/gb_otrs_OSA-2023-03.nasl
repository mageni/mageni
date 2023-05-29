# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149665");
  script_version("2023-05-11T09:09:33+0000");
  script_tag(name:"last_modification", value:"2023-05-11 09:09:33 +0000 (Thu, 11 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-11 06:49:59 +0000 (Thu, 11 May 2023)");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:C/A:P");

  script_cve_id("CVE-2023-2534");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS 8.0.x < 8.0.32 Information Disclosure / DoS Vulnerability (OSA-2023-03)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to a information and denial of service (DoS)
  vulnerability via websocket push events.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper authorization vulnerability in OTRS (Websocket API
  backend) allows any as Agent authenticated attacker to track user behaviour and to gain live
  insight into overall system usage. User IDs can easily be correlated with real names e. g. via
  ticket histories by any user. (Fuzzing for garnering other adjacent user/sensitive data).
  Subscribing to all possible push events could also lead to performance implications on the server
  side, depending on the size of the installation and the number of active users. (Flooding)");

  script_tag(name:"affected", value:"OTRS version 8.0.x through 8.0.31.");

  script_tag(name:"solution", value:"Update to version 8.0.32 or later.");

  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2023-03/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
