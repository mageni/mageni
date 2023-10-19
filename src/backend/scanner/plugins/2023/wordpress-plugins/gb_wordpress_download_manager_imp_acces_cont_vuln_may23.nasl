# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpdownloadmanager:wordpress_download_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126402");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-05 17:08:38 +0000 (Mon, 05 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-05 14:48:00 +0000 (Mon, 05 Jun 2023)");

  script_cve_id("CVE-2023-1524");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Download Manager Plugin < 3.2.71 Improper Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/download-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Download Manager' is prone to an improper
  access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not adequately validate passwords for
  password-protected files. Upon validation, a master key is generated and exposed to the user,
  which may be used to download any password-protected file on the server, allowing a user to
  download any file with the knowledge of anyone file's password.");

  script_tag(name:"affected", value:"WordPress Download Manager plugin prior to version 3.2.71.");

  script_tag(name:"solution", value:"Update to version 3.2.71 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/3802d15d-9bfd-4762-ab8a-04475451868e");

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

if (version_is_less_equal(version: version, test_version: "3.2.71")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.71", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
