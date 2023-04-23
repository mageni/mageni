# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:apache:archiva';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149477");
  script_version("2023-04-03T10:10:12+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:10:12 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-03 03:31:09 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-28158");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Archiva 2.x < 2.2.10 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_apache_archiva_detect.nasl");
  script_mandatory_keys("apache_archiva/installed");

  script_tag(name:"summary", value:"Apache Archiva is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Privilege escalation via stored XSS using the file upload
  service to upload malicious content. The issue can be exploited only by authenticated users which
  can create directory name to inject some XSS content and gain some privileges such admin user.");

  script_tag(name:"affected", value:"Apache Archiva version 2.x through 2.2.9.");

  script_tag(name:"solution", value:"Upgrade to version 2.2.10 or later.");

  script_xref(name:"URL", value:"https://archiva.apache.org/docs/2.2.10/release-notes.html");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/8pm6d5y9cptznm0bdny3n8voovmm0dtt");

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

if (version_in_range_exclusive(version: version, test_version_lo: "2.0.0", test_version_up: "2.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
