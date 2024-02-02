# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170697");
  script_version("2023-11-21T05:05:52+0000");
  script_tag(name:"last_modification", value:"2023-11-21 05:05:52 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-14 11:29:22 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-17 20:20:00 +0000 (Fri, 17 Nov 2023)");

  script_cve_id("CVE-2023-45806", "CVE-2023-45816", "CVE-2023-46130", "CVE-2023-47119",
                "CVE-2023-47121");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 3.1.3, 3.2.x < 3.2.0.beta3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-45806: DoS via regexp injection in Full Name

  - CVE-2023-45816: Unread bookmark reminder notifications that the user cannot access can be seen

  - CVE-2023-46130: Bypassing height value allowed in some theme components

  - CVE-2023-47119: HTML injection in oneboxed links

  - CVE-2023-47121: SSRF vulnerability in Embedding");

  script_tag(name:"affected", value:"Discourse prior to version 3.1.3 and 3.2.x prior to
  3.2.0.beta3.");

  script_tag(name:"solution", value:"Update to version 3.1.3, 3.2.0.beta3 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-hcgf-hg2g-mw78");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-v9r6-92wp-f6cf");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-c876-638r-vfcg");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-j95w-5hvx-jp5w");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-hp24-94qf-8cgc");

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

if (version_is_less(version: version, test_version: "3.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.2.0.beta1", test_version_up: "3.2.0.beta3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.0.beta3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
