# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.126303");
  script_version("2023-05-10T09:37:12+0000");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-04 12:30:56 +0200 (Thu, 04 May 2023)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");

  script_cve_id("CVE-2023-2427", "CVE-2023-2428", "CVE-2023-2429", "CVE-2023-2550");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpmyFAQ < 3.1.13 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-2427: Reflected XSS

  - CVE-2023-2428: Stored cross site scripting vulnerability in name field in add question module.

  - CVE-2023-2429: Application does not properly validate email addresses when updating user
  profiles. This vulnerability allows an attacker to manipulate their email address and change it
  to another email address that is already registered in the system, including email addresses
  belonging to other users such as the administrator. Once the attacker has control of the other
  user's email address, they can request to remove the user from the system, leading to a loss of
  data and access.

  - CVE-2023-2550: Stored XSS");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.1.13.");

  script_tag(name:"solution", value:"Update to version 3.1.13 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/89005a6d-d019-4cb7-ae88-486d2d44190d");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/cee65b6d-b003-4e6a-9d14-89aa94bee43e/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/20d3a0b3-2693-4bf1-b196-10741201a540/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/840c8d91-c97e-4116-a9f8-4ab1a38d239b");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.1.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.13");
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
