# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodebb:nodebb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126497");
  script_version("2023-10-03T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-10-03 05:05:26 +0000 (Tue, 03 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-28 08:36:00 +0000 (Thu, 28 Sep 2023)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");

  script_cve_id("CVE-2022-46164");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NodeBB < 2.6.1 Account Takeover Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_nodebb_detect.nasl");
  script_mandatory_keys("NodeBB/installed");

  script_tag(name:"summary", value:"NodeBB is prone to an account takeover vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to a plain object with a prototype being used in socket.io
  message handling a specially crafted payload can be used to impersonate other users and takeover
  accounts.");

  script_tag(name:"affected", value:"NodeBB prior to version 2.6.1.");

  script_tag(name:"solution", value:"Update to version 2.6.1 or later.");

  script_xref(name:"URL", value:"https://github.com/NodeBB/NodeBB/security/advisories/GHSA-rf3g-v8p5-p675");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version:version, test_version: "2.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.6.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
