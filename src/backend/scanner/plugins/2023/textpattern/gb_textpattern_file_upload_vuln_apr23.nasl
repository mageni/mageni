# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:textpattern:textpattern";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170417");
  script_version("2023-04-18T10:10:05+0000");
  script_tag(name:"last_modification", value:"2023-04-18 10:10:05 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-17 12:57:35 +0000 (Mon, 17 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2023-26852");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Textpattern CMS <= 4.8.8 Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_textpattern_cms_http_detect.nasl");
  script_mandatory_keys("textpattern_cms/detected");

  script_tag(name:"summary", value:"Textpattern CMS is prone to an arbitrary file upload
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Textpattern CMS allows privileged users such as admin to upload
  a .php file via upload and install plugins.");

  script_tag(name:"affected", value:"Textpattern CMS version 4.8.8 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 17th April, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/leekenghwa/CVE-2023-26852-Textpattern-v4.8.8-and-");

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

if (version_is_less(version: version, test_version: "4.8.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
