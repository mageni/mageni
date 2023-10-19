# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:h2o_project:h2o";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170600");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-12 12:29:42 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-14 01:15:00 +0000 (Sat, 14 Oct 2023)");

  script_cve_id("CVE-2023-44487");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("H2O HTTP Server HTTP/2 Protocol DoS Vulnerability (GHSA-2m7v-gc89-fjqf)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_h2o_http_server_detect.nasl");
  script_mandatory_keys("h2o/installed");

  script_tag(name:"summary", value:"H2O is prone to a denial of service (DoS) vulnerability in the
  HTTP/2 protocol.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The HTTP/2 protocol allows a denial of service (server resource
  consumption) because request cancellation can reset many streams quickly, as exploited in the wild
  in August through October 2023.

  The flaw is also known as HTTP/2 Rapid Reset Attack.");

  script_tag(name:"impact", value:"This vulnerability allows a remote, unauthenticated attacker to
  cause an increase in CPU usage that can lead to a denial-of-service (DoS).");

  script_tag(name:"affected", value:"H2O version 2.2.6 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 12th October, 2023.
  Information regarding this issue will be updated once solution details are available.

  Note: The vendor has added a fix into the master repository with commit '28fe151'.");

  script_xref(name:"URL", value:"https://github.com/h2o/h2o/security/advisories/GHSA-2m7v-gc89-fjqf");
  script_xref(name:"URL", value:"https://github.com/h2o/h2o/pull/3291");
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

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

report = report_fixed_ver(installed_version: version, fixed_version: "None");
security_message(port: port, data: report);
exit(0);
