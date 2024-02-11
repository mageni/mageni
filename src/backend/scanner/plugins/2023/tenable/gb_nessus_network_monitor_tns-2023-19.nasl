# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_network_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170475");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2023-05-17 09:49:53 +0000 (Wed, 17 May 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-25 18:46:00 +0000 (Fri, 25 Feb 2022)");

  script_cve_id("CVE-2022-40674", "CVE-2022-25315", "CVE-2022-25314", "CVE-2022-25236",
                "CVE-2022-25235", "CVE-2022-23990", "CVE-2022-23852", "CVE-2022-22827",
                "CVE-2022-22826", "CVE-2022-22825", "CVE-2022-22824", "CVE-2022-22823",
                "CVE-2022-22822", "CVE-2021-46143", "CVE-2021-45960", "CVE-2022-4304",
                "CVE-2022-4450", "CVE-2023-0215", "CVE-2023-0216", "CVE-2023-0217",
                "CVE-2023-0401", "CVE-2022-4203");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Network Monitor < 6.2.1 Multiple Vulnerabilities (TNS-2023-19)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nnm_smb_login_detect.nasl");
  script_mandatory_keys("tenable/nessus_network_monitor/detected");

  script_tag(name:"summary", value:"Tenable Nessus Network Monitor is prone multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nessus Network Monitor leverages third-party software to help
  provide underlying functionality. Several of the third-party components (OpenSSL, expat) were found
  to contain vulnerabilities, and updated versions have been made available by the providers.

  Nessus Network Monitor 6.2.1 updates OpenSSL to version 3.0.8 and expat to version 2.5.0 to address
  the identified vulnerabilities.");

  script_tag(name:"affected", value:"Tenable Nessus Network Monitor prior to version 6.2.1.");

  script_tag(name:"solution", value:"Update to version 6.2.1 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-19");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "6.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
