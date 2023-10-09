# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150995");
  script_version("2023-09-19T05:06:03+0000");
  script_tag(name:"last_modification", value:"2023-09-19 05:06:03 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-04-21 05:07:44 +0000 (Fri, 21 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2023-38706", "CVE-2023-40588", "CVE-2023-41042", "CVE-2023-41043");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 3.1.x - 3.1.0.beta8 Multiple DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-38706: DoS via drafts

  - CVE-2023-40588: DoS via 2FA and Security Key Names

  - CVE-2023-41042: DoS via remote theme assets

  - CVE-2023-41043: DoS via SvgSprite cache");

  script_tag(name:"affected", value:"Discourse versions 3.1.x through 3.1.0.beta8.");

  script_tag(name:"solution", value:"Update to version 3.2.0.beta1 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-7wpp-4pqg-gvp8");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-2hg5-3xm3-9vvx");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-2fq5-x3mm-v254");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-28hh-h5xw-xgvx");

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

if (version_in_range(version: version, test_version: "3.1.0.beta", test_version2: "3.1.0.beta8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.0.beta1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
