# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openmediavault:openmediavault";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102068");
  script_version("2023-09-28T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-09-28 05:05:04 +0000 (Thu, 28 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-25 08:27:17 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-21 15:10:00 +0000 (Fri, 21 Jul 2017)");

  script_cve_id("CVE-2017-1000065");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Openmediavault 2.1 - 3.0.66 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openmediavault_ssh_detect.nasl");
  script_mandatory_keys("openmediavault/detected");

  script_tag(name:"summary", value:"Openmediavault is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple Cross-site scripting (XSS) vulnerabilities in rpc.php
  in OpenMediaVault release 2.1 in Access Rights Management(Users) functionality allows attackers to
  inject arbitrary web scripts and execute malicious scripts within an authenticated client's
  browser.");

  script_tag(name:"affected", value:"Openmediavault versions 2.1 through 3.0.66.");

  script_tag(name:"solution", value:"Update to version 3.0.67 or later.");

  script_xref(name:"URL", value:"https://github.com/openmediavault/openmediavault/commit/b2db1e24d0e52b961b5c3b3329b6ee717cac53a2");
  script_xref(name:"URL", value:"https://github.com/openmediavault/openmediavault/commit/529fa8d5defbeb16157ef2447ca152d5ac9b0927");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range_exclusive(version:vers, test_version_lo:"2.1", test_version_up:"3.0.67")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.0.67", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
