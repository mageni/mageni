# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170603");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-12 15:46:12 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-14 01:15:00 +0000 (Sat, 14 Oct 2023)");

  script_cve_id("CVE-2023-45143", "CVE-2023-44487", "CVE-2023-39331", "CVE-2023-39332",
                "CVE-2023-38552", "CVE-2023-39333");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 18.x < 18.18.2, 20.x < 20.8.1 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nodejs_detect_win.nasl");
  script_mandatory_keys("Nodejs/Win/Ver");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-45143: Cookie headers are not cleared in cross-domain redirect in undici-fetch

  - CVE-2023-44487: HTTP/2 Rapid Reset

  - CVE-2023-39331: Permission model improperly protects against path traversal

  - CVE-2023-39332: Path traversal through path stored in Uint8Array

  - CVE-2023-38552: Integrity checks according to policies can be circumvented

  - CVE-2023-39333: Code injection via WebAssembly export names");

  script_tag(name:"affected", value:"Node.js versions 18.x and 20.x.

  - CVE-2023-44487: This vulnerability affects all users of HTTP/2 servers in all active release
  lines 18.x and 20.x

  - CVE-2023-39331, CVE-2023-39332: This vulnerability affects all users using the experimental
  permission model in Node.js 20.x

  - CVE-2023-38552: This vulnerability affects all users using the experimental policy mechanism in
  all active release lines: 18.x and, 20.x

  - CVE-2023-39333: This vulnerability affects users of the --experimental-wasm-modules command line
  option in all active release lines 18.x and 20.x");

  script_tag(name:"solution", value:"Update to version 18.18.2, 20.8.1 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/october-2023-security-releases");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/50121");
  script_xref(name:"URL", value:"https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack");
  script_xref(name:"URL", value:"https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/");
  script_xref(name:"URL", value:"https://aws.amazon.com/blogs/security/how-aws-protects-customers-from-ddos-events/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/10/6");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "18.0", test_version_up: "18.18.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.18.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "20.0", test_version_up: "20.8.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.8.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
