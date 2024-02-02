# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100765");
  script_version("2023-11-16T05:05:14+0000");
  script_tag(name:"last_modification", value:"2023-11-16 05:05:14 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-23 15:46:30 +0000 (Mon, 23 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-13 20:02:00 +0000 (Mon, 13 Nov 2023)");

  script_cve_id("CVE-2023-46846");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid Request/Response Smuggling Vulnerability (GHSA-j83v-w3p4-5cqh, SQUID-2023:1)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to a request/response smuggling vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to chunked decoder lenience Squid is vulnerable to
  Request/Response smuggling attacks when parsing HTTP/1.1 and ICAP messages.");

  script_tag(name:"affected", value:"Squid versions 2.6 through 6.3.");

  script_tag(name:"solution", value:"Update to version 6.4 or later.");

  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-j83v-w3p4-5cqh");

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

if (version_in_range(version: version, test_version: "2.6", test_version2: "6.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
