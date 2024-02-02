# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126366");
  script_version("2023-10-24T14:40:27+0000");
  script_tag(name:"last_modification", value:"2023-10-24 14:40:27 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-02-09 12:25:34 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-10517", "CVE-2018-1000158");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("CMS Made Simple <= 2.2.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2018-10517: The module import operation in the admin dashboard contains a remote code
  execution, exploitable by an admin user, because an XML Package can contain base64-encoded PHP
  code in a data element

  - CVE-2018-1000158: Incorrect Access Control vulnerability in the function of send_recovery_email
  that can result in Administrator Password Reset Poisoning, specifically a reset URL pointing at an
  attacker controlled server can be created by using a host header attack");

  script_tag(name:"affected", value:"CMS Made Simple version 2.2.7 and prior.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/150173/CMS-Made-Simple-2.2.7-Remote-Code-Execution.html");

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

if (version_is_less_equal(version: version, test_version: "2.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
