# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150942");
  script_version("2023-09-08T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-09-08 05:06:21 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-07 04:55:56 +0000 (Thu, 07 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid DoS Vulnerability (GHSA-jm7h-w5q5-jpq9, SQUID-2020:13)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This problem allows a remote gopher: server to trigger a buffer
  overflow by delivering large gopher protocol responses. On most operating systems with memory
  protection this will halt Squid service immediately, causing a denial of service to all Squid
  clients.

  The gopher protocol is always available and enabled in Squid prior to Squid 6.0.1.");

  script_tag(name:"affected", value:"Squid prior to version 6.0.1.");

  script_tag(name:"solution", value:"Update to version 6.0.1 or later.

  As a workaround reject all gopher URL requests. Please see the referenced vendor advisory for more
  information.");

  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-jm7h-w5q5-jpq9");

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

if (version_is_less(version: version, test_version: "6.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
