# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.124323");
  script_version("2023-05-25T09:08:46+0000");
  script_tag(name:"last_modification", value:"2023-05-25 09:08:46 +0000 (Thu, 25 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-18 08:30:56 +0200 (Thu, 18 May 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2023-2752", "CVE-2023-2753");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpmyFAQ < 3.2.0-beta Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-2752: Stored XSS at FAQ Answer

  - CVE-2023-2753: Stored XSS due to insufficient filtering in FAQ");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.2.0-beta.");

  script_tag(name:"solution", value:"Update to version 3.2.0-beta or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/efdf5b24-6d30-4d57-a5b0-13b253ba3ea4");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/eca2284d-e81a-4ab8-91bb-7afeca557628");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.2.0-beta")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.0-beta");
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
