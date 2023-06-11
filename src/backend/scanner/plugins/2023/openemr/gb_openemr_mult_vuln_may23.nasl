# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126378");
  script_version("2023-06-02T09:09:16+0000");
  script_tag(name:"last_modification", value:"2023-06-02 09:09:16 +0000 (Fri, 02 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-10 12:47:25 +0000 (Wed, 10 May 2023)");
  script_tag(name:"cvss_base", value:"7.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:P/A:P");

  script_cve_id("CVE-2023-2566", "CVE-2023-2674", "CVE-2023-2942", "CVE-2023-2943",
                "CVE-2023-2944", "CVE-2023-2945", "CVE-2023-2946", "CVE-2023-2947",
                "CVE-2023-2948", "CVE-2023-2949", "CVE-2023-2950");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR < 7.0.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value:"OpenEMR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-2566: Stored XSS bypass the protection rules

  - CVE-2023-2674: Broken Access Controls in Practice settings

  - CVE-2023-2942: Bypass client side restrictions leads to IDOR on creating appointment.

  - CVE-2023-2943: Stored HTML injection in Patient chat functionality

  - CVE-2023-2944: Access Control in Admin Address Book

  - CVE-2023-2945: Missing Authorization Check Allows Impersonated Secure Messages.

  - CVE-2023-2946: Access Control in Prescription Controller

  - CVE-2023-2947: Stored XSS in Admin Panel

  - CVE-2023-2948: Reflected XSS in /library/custom_template/share_template.php

  - CVE-2023-2949: Reflected XSS in interface/forms/eye_mag/js/eye_base.php

  - CVE-2023-2950: Patient ability to rewrite it's own documents leads to HTML injection.");

  script_tag(name:"affected", value:"OpenEMR prior to version 7.0.1.");

  script_tag(name:"solution", value:"Update to version 7.0.1 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/47d6fc2a-989a-44eb-9cb7-ab4f8bd44496/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/af73e913-730c-4245-88ce-26fc908d3644/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/dd56e7a0-9dff-48fc-bc59-9a22d91869eb/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/4190f944-dc2c-4624-9abf-31479456faa9/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/0d67dcb1-acc0-4d5d-bb69-a09d1bc9fa1d/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/62de71bd-333d-4593-91a5-534ef7f0c435/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/52534def-acab-4200-a79a-89ef4ce6a0b0/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/e550f4b0-945c-4886-af7f-ee0dc30b2a08/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/3842486f-38b1-4150-9f78-b81d0ae580c4/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/612d13cf-2ef9-44ea-b8fb-e797948a9a86/");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "7.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

