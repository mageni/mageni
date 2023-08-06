# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150796");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-07-31 04:01:53 +0000 (Mon, 31 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:N");

  script_cve_id("CVE-2023-37904", "CVE-2023-37906", "CVE-2023-38684", "CVE-2023-38685");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 3.0.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-37904: Race Condition in Accept Invite

  - CVE-2023-37906: DoS via post edit reason

  - CVE-2023-38684: Possible DDoS due to unbounded limits in various controller actions

  - CVE-2023-38685: Restricted tag information visible to unauthenticated users");

  script_tag(name:"affected", value:"Discourse prior to version 3.0.6.");

  script_tag(name:"solution", value:"Update to version 3.0.6 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-6wj5-4ph2-c7qg");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-pjv6-47x6-mx7c");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-ff7g-xv79-hgmf");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-wx6x-q4gp-mgv5");

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

if (version_is_less(version: version, test_version: "3.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
