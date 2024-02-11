# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118416");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2022-11-11 13:40:06 +0000 (Fri, 11 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-11 18:38:00 +0000 (Thu, 11 Aug 2022)");

  script_cve_id("CVE-2020-28458", "CVE-2021-23445", "CVE-2022-31129", "CVE-2022-24785",
                "CVE-2022-40674", "CVE-2022-2309", "CVE-2022-29824", "CVE-2022-23308",
                "CVE-2022-37434");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 10.3.1 Multiple Vulnerabilities (TNS-2022-20)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tenable Nessus leverages third-party software to help provide
  underlying functionality. Several of the third-party components (moment.js, expat, datatables,
  libxml2, zlib) were found to contain vulnerabilities, and updated versions have been made
  available by the providers.

  Nessus 10.3.1 updates moment.js to version 2.29.4, expat to version 2.4.9, datatables to version
  1.10.21, libxml2 to 2.10.3 and zlib to 1.2.13 to address the identified vulnerabilities.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 10.3.1.");

  script_tag(name:"solution", value:"Update to version 10.3.1 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2022-20");

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

if (version_is_less(version: version, test_version: "10.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
