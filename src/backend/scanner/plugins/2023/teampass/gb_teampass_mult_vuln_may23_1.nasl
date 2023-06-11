# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teampass:teampass";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124319");
  script_version("2023-06-05T09:09:07+0000");
  script_tag(name:"last_modification", value:"2023-06-05 09:09:07 +0000 (Mon, 05 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-08 08:05:24 +0000 (Mon, 08 May 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:N");

  script_cve_id("CVE-2023-2516", "CVE-2023-2591");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TeamPass < 3.0.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_teampass_http_detect.nasl");
  script_mandatory_keys("teampass/detected");

  script_tag(name:"summary", value:"TeamPass is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-2516: Stored XSS on function item with folder

  - CVE-2023-2591: Stored HTML injection in Item Label");

  script_tag(name:"affected", value:"TeamPass prior to version 3.0.7.");

  script_tag(name:"solution", value:"Update to version 3.0.7 or later."); #NOTE: detection fails in versions 3.0.0 and higher

  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/teampass/commit/39b774cba118ca5383b0a51a71b1e7dea2761927");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/19470f0b-7094-4339-8d4a-4b5570b54716/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/705f79f4-f5e3-41d7-82a5-f00441cd984b/");

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

if (version_is_less(version: version, test_version: "3.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.7", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
