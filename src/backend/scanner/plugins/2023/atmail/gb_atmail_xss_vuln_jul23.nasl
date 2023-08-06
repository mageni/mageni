# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:atmail:atmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124382");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-07-31 07:58:33 +0000 (Mon, 31 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2022-31200");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Atmail <= 5.62 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("atmail_detect.nasl");
  script_mandatory_keys("Atmail/installed");

  script_tag(name:"summary", value:"Atmail is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"insight", value:"Atmail allows cross-site scripting via the
  mail/parse.php?file=html/$this-%3ELanguage/help/filexp.html&FirstLoad=1&HelpFile=file.html
  Search Terms field.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Atmail version 5.62 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 31th July, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://medium.com/@rohitgautam26/cve-2022-31200-5117bac8d548");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

ver = infos["version"];
path = infos["location"];

if (version_is_less_equal(version: ver, test_version: "5.62")) {
  report = report_fixed_ver(installed_version: ver, fixed_version: "None", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
