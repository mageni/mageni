# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitea:gitea";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126467");
  script_version("2023-08-29T05:06:28+0000");
  script_tag(name:"last_modification", value:"2023-08-29 05:06:28 +0000 (Tue, 29 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-24 18:49:38 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gitea 1.20.x < 1.20.1 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitea_http_detect.nasl");
  script_mandatory_keys("gitea/detected");

  script_tag(name:"summary", value:"Gitea is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It was possible to use the javascript:, vbscript: and data: URL
  schemes, which can directly execute code on your computer.");

  script_tag(name:"affected", value:"Gitea version 1.20.x prior to 1.20.1.");

  script_tag(name:"solution", value:"Update to version 1.20.1 or later.");

  script_xref(name:"URL", value:"https://blog.gitea.com/release-of-1.20.1/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.20.0", test_version_up: "1.20.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.20.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
