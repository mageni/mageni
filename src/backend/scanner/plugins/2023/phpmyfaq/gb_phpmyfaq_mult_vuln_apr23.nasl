# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.126038");
  script_version("2023-04-12T11:20:00+0000");
  script_tag(name:"last_modification", value:"2023-04-12 11:20:00 +0000 (Wed, 12 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-04 10:30:56 +0200 (Tue, 04 Apr 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2023-1753", "CVE-2023-1754", "CVE-2023-1755", "CVE-2023-1756",
                "CVE-2023-1757", "CVE-2023-1758", "CVE-2023-1759", "CVE-2023-1760",
                "CVE-2023-1761", "CVE-2023-1762", "CVE-2023-1878", "CVE-2023-1879",
                "CVE-2023-1880", "CVE-2023-1882", "CVE-2023-1883", "CVE-2023-1884",
                "CVE-2023-1885", "CVE-2023-1886", "CVE-2023-1887");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpmyFAQ < 3.1.12 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-1753: Weak password policy while creating a new user with the Admin account

  - CVE-2023-1754: The product does not neutralize or incorrectly neutralizes user-controllable
  input before it is placed in output that is used as a web page that is served to other users.

  - CVE-2023-1755: Stored XSS in Configuration Version

  - CVE-2023-1756: Stored XSS after XSS Filter Bypass through exporting an HTML-Document

  - CVE-2023-1757: XSS in hyperlink when create FAQ News

  - CVE-2023-1758: XSS in Comment Faq news username parameter

  - CVE-2023-1759: The product does not neutralize or incorrectly neutralizes user-controllable
  input before it is placed in output that is used as a web page that is served to other users.

  - CVE-2023-1760: In the admin account, there is a feature to add a user. In this feature, an
  XSS was found in the `Your Name` form.

  - CVE-2023-1761: Stored HTML-Injection in the Comments Part

  - CVE-2023-1762: Privilege escalation from user with `add user` to super admin

  - CVE-2023-1878: Stored XSS in the adminlog functionality

  - CVE-2023-1879: Stored XSS @ updatecategory

  - CVE-2023-1880: Reflected XSS in send2friend.php

  - CVE-2023-1882: Stored XSS edit Config Link

  - CVE-2023-1883: Broken access control - still someone can comment in unactive FAQ NEWS

  - CVE-2023-1884: XSS @ Stop Words

  - CVE-2023-1885: Stored XSS in the Category Field Name

  - CVE-2023-1886: Captcha Bypass allows sending unlimited Comments

  - CVE-2023-1887: User with only edit can delete post and sometimes can add post.");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.1.12.");

  script_tag(name:"solution", value:"Update to version 3.1.12 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/01d6ae23-3a8f-42a8-99f4-10246187d71b/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/529f2361-eb2e-476f-b7ef-4e561a712e28/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/882ffa07-5397-4dbb-886f-4626859d711a/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/e495b443-b328-42f5-aed5-d68b929b4cb9/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/584a200a-6ff8-4d53-a3c0-e7893edff60c/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/0854328e-eb00-41a3-9573-8da8f00e369c/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/e8109aed-d364-4c0c-9545-4de0347b10e1/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/2d0ac48a-490d-4548-8d98-7447042dd1b5/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/24c0a65f-0751-4ff8-af63-4b325ac8879f/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/3c2374cc-7082-44b7-a6a6-ccff7a650a3a/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/93f981a3-231d-460d-a239-bb960e8c2fdc/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/1dc7f818-c8ea-4f80-b000-31b48a426334/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/ece5f051-674e-4919-b998-594714910f9e/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/8ab09a1c-cfd5-4ce0-aae3-d33c93318957/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/2f1e417d-cf64-4cfb-954b-3a9cb2f38191/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/dda73cb6-9344-4822-97a1-2e31efb6a73e/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/bce84c02-abb2-474f-a67b-1468c9dcabb8/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/b7d244b7-5ac3-4964-81ee-8dbb5bb5e33a/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/e4a58835-96b5-412c-a17e-3ceed30231e1/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.1.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.12");
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
