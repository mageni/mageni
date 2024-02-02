# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpdeveloper:essential_blocks";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126517");
  script_version("2023-11-07T05:06:14+0000");
  script_tag(name:"last_modification", value:"2023-11-07 05:06:14 +0000 (Tue, 07 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-02 09:44:07 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-27 17:37:00 +0000 (Fri, 27 Oct 2023)");

  script_cve_id("CVE-2023-4386", "CVE-2023-4402");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Essential Blocks Plugin < 4.2.1 Multiple PHP Object Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/essential-blocks/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Essential Blocks' is prone to multiple PHP
  object injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-4386: PHP object injection via deserialization of untrusted input in the get_posts
  function.

  - CVE-2023-4402: PHP object injection via deserialization of untrusted input in the get_products
  function.");

  script_tag(name:"affected", value:"WordPress Essential Blocks plugin prior to version 4.2.1.");

  script_tag(name:"solution", value:"Update to version 4.2.1 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/af468f83-d6ad-474c-bf7f-c4eeb6df1b54");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/1ede7a25-9bb2-408e-b7fb-e5bd4f594351");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
