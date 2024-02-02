# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170615");
  script_version("2023-10-25T11:49:00+0000");
  script_tag(name:"last_modification", value:"2023-10-25 11:49:00 +0000 (Wed, 25 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-23 10:38:49 +0000 (Mon, 23 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-20 17:32:00 +0000 (Fri, 20 Oct 2023)");

  script_cve_id("CVE-2023-43659", "CVE-2023-43814", "CVE-2023-44388", "CVE-2023-44391",
                "CVE-2023-45147");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse <= 3.1.1, 3.2.0.beta1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-43659: XSS via email preview when CSP disabled

  - CVE-2023-43814: Exposure of poll options and votes to unauthorized users

  - CVE-2023-44388: Malicious requests can fill up the log files resulting in a DoS on the server

  - CVE-2023-44391: Prevent unauthorized access to summary details

  - CVE-2023-45147: Arbitrary keys can be added to a topic's custom fields by any user");

  script_tag(name:"affected", value:"Discourse prior to version 3.1.2 and 3.2.0.beta1.");

  script_tag(name:"solution", value:"Update to version 3.1.2, 3.2.0.beta2 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-g4qg-5q2h-m8ph");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-3x57-846g-7qcw");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-89h3-g746-xmwq");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-7px5-fqcf-7mfr");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-wm89-m359-f9qv");

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

if (version_is_less(version: version, test_version: "3.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.2.0.beta1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.0.beta2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
