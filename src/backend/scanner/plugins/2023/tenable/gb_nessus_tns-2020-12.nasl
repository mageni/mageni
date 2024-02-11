# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170468");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2023-05-17 09:49:53 +0000 (Wed, 17 May 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2020-1967", "CVE-2020-1971");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 8.13.1 Multiple Vulnerabilities (TNS-2020-12)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple vulnerabilities in OpenSSL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tenable Nessus leverages third-party software to help provide underlying
  functionality. One third-party component (OpenSSL) was found to contain vulnerabilities, and updated
  versions have been made available by the providers.

  Nessus version 8.13.1 will update OpenSSL to 1.1.1i to address the identified vulnerabilities.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 8.13.1.");

  script_tag(name:"solution", value:"Update to version 8.13.1 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2020-12");

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

if (version_is_less(version: version, test_version: "8.13.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.13.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
