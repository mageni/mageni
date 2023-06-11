# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teampass:teampass";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126342");
  script_version("2023-06-05T09:09:07+0000");
  script_tag(name:"last_modification", value:"2023-06-05 09:09:07 +0000 (Mon, 05 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-25 10:20:24 +0000 (Thu, 25 May 2023)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2023-2859", "CVE-2023-3009", "CVE-2023-3083", "CVE-2023-3084",
                "CVE-2023-3086", "CVE-2023-3095");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TeamPass < 3.0.9 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_teampass_http_detect.nasl");
  script_mandatory_keys("teampass/detected");

  script_tag(name:"summary", value:"TeamPass is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-2859: Stored HTML injection in folderName affecting Admin

  - CVE-2023-3009: Stored cross-site scripting (XSS) on item name

  - CVE-2023-3083, CVE-2023-3084, CVE-2023-3086: Multiple stored XSS

  - CVE-2023-3095: Improper Access Control");

  script_tag(name:"affected", value:"TeamPass prior to version 3.0.9.");

  script_tag(name:"solution", value:"Update to version 3.0.9 or later."); #NOTE: detection fails in versions 3.0.0 and higher

  script_xref(name:"URL", value:"https://huntr.dev/bounties/d7b8ea75-c74a-4721-89bb-12e5c80fb0ba/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/2929faca-5822-4636-8f04-ca5e0001361f/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/4b86b56b-c51b-4be8-8ee4-6e385d1e9e8a");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/17be9e8a-abe8-41db-987f-1d5b0686ae20");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/35c899a9-40a0-4e17-bfb5-2a1430bc83c4");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/c6b29e46-02e0-43ad-920f-28ac482ea2ab");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "3.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.9", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
