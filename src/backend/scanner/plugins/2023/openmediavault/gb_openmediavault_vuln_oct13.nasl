# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openmediavault:openmediavault";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102067");
  script_version("2023-09-28T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-09-28 05:05:04 +0000 (Thu, 28 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-25 08:27:17 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2013-3632");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Openmediavault < 0.5.32 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_openmediavault_ssh_detect.nasl");
  script_mandatory_keys("openmediavault/detected");

  script_tag(name:"summary", value:"Openmediavault is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Cron service in rpc.php in OpenMediaVault allows remote
  authenticated users to execute cron jobs as arbitrary users and execute arbitrary commands via the
  username parameter.");

  script_tag(name:"affected", value:"Openmediavault prior to version 0.5.32.");

  script_tag(name:"solution", value:"Update to version 0.5.32 or later and disable the root user for cron jobs.");

  script_xref(name:"URL", value:"https://forum.openmediavault.org/index.php?thread/6494-cve-2013-3632/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"0.5.32")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.5.32", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
