# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118405");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2022-11-07 12:54:42 +0000 (Mon, 07 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-22 19:49:00 +0000 (Wed, 22 Sep 2021)");

  script_cve_id("CVE-2021-23358");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 10.1.0 Arbitrary Code Injection Vulnerability (TNS-2022-04)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to an arbitrary code injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tenable Nessus leverages third-party software to help provide
  underlying functionality. One of the third-party components (Underscore.js) was found
  to contain a vulnerability, and an updated version has been made available by the
  provider. Nessus 10.1.0 updates Underscore.js to version 1.13.1 to address the identified
  vulnerability.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 10.1.0.");

  script_tag(name:"solution", value:"Update to version 10.1.0 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2022-04");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "10.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
