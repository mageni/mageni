# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:jspwiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124331");
  script_version("2023-06-07T05:05:00+0000");
  script_tag(name:"last_modification", value:"2023-06-07 05:05:00 +0000 (Wed, 07 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-30 08:05:01 +0000 (Tue, 30 May 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2022-46907");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache JSPWiki < 2.12.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_jspwiki_http_detect.nasl");
  script_mandatory_keys("apache/jspwiki/detected");

  script_tag(name:"summary", value:"Apache JSPWiki is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A carefully crafted request on several JSPWiki plugins could
  trigger an XSS on Apache JSPWiki, which could allow the attacker to execute
  javascript in the victim's browser and get some sensitive information about the victim.");

  script_tag(name:"affected", value:"Apache JSPWiki prior to version 2.12.0.");

  script_tag(name:"solution", value:"Update to version 2.12.0 or later.");

  script_xref(name:"URL", value:"https://jspwiki-wiki.apache.org/Wiki.jsp?page=CVE-2022-46907");

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

if (version_is_less(version: version, test_version: "2.12.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.12.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
