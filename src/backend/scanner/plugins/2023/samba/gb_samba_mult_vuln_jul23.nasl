# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104872");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-20 13:30:44 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-2127", "CVE-2023-34966", "CVE-2023-34967", "CVE-2023-34968");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba Multiple Vulnerabilities (Jul 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2022-2127: Out-Of-Bounds read in winbind AUTH_CRAP

  - CVE-2023-34966: Samba Spotlight mdssvc RPC Request Infinite Loop Denial-of-Service Vulnerability

  - CVE-2023-34967: Samba Spotlight mdssvc RPC Request Type Confusion Denial-of-Service
  Vulnerability

  - CVE-2023-34968: Spotlight server-side Share Path Disclosure");

  script_tag(name:"affected", value:"All versions of Samba up to 4.16.10, 4.17.9 and 4.18.4.");

  script_tag(name:"solution", value:"Update to version 4.16.11, 4.17.10, 4.18.5 or later.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-2127.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-34966.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-34967.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-34968.html");

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

if (version_is_less(version: version, test_version: "4.16.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.16.11 / 4.17.10 / 4.18.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.17.0", test_version_up: "4.17.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.17.10 / 4.18.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.18.0", test_version_up: "4.18.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.18.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
