# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:couchdb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114221");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-13 16:41:58 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-20 18:32:00 +0000 (Wed, 20 Dec 2023)");

  script_cve_id("CVE-2023-45725");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache CouchDB < 3.3.3 Privilege Escalation Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_apache_couchdb_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/couchdb/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache CouchDB is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Design document functions which receive a user http request
  object may expose authorization or session cookie headers of the user who accesses the
  document.");

  script_tag(name:"affected", value:"Apache CouchDB version 3.3.2 and prior.");

  script_tag(name:"solution", value:"Update to version 3.3.3 or later.");

  script_xref(name:"URL", value:"https://docs.couchdb.org/en/stable/cve/2023-45725.html");

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

if (version_is_less(version: version, test_version: "3.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
