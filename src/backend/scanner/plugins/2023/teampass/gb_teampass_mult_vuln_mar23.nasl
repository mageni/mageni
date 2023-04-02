# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teampass:teampass";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126029");
  script_version("2023-03-27T10:09:49+0000");
  script_tag(name:"last_modification", value:"2023-03-27 10:09:49 +0000 (Mon, 27 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-10 10:05:24 +0000 (Fri, 10 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-1463", "CVE-2023-1545");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TeamPass < 3.0.0.23 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_teampass_http_detect.nasl");
  script_mandatory_keys("teampass/detected");

  script_tag(name:"summary", value:"TeamPass is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-1463: IDOR vulnerability allow low level user to log out everyone in the system by
  changing the user ID.

  - CVE-2023-1545: SQL injection in API authorization check.");

  script_tag(name:"affected", value:"TeamPass prior to version 3.0.0.23.");

  script_tag(name:"solution", value:"Update to version 3.0.0.23 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/f6683c3b-a0f2-4615-b639-1920c8ae12e6/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/942c015f-7486-49b1-94ae-b1538d812bc2/");

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

if (version_is_less(version: version, test_version: "3.0.0.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.0.23", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
