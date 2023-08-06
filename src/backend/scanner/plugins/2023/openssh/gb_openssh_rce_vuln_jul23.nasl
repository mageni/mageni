# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104869");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-20 09:29:09 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2023-38408");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenBSD OpenSSH < 9.3p2 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"summary", value:"OpenBSD OpenSSH is prone to a remote code execution (RCE)
  vulnerability in OpenSSH's forwarded ssh-agent.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A condition where specific libraries loaded via ssh-agent(1)'s
  PKCS#11 support could be abused to achieve remote code execution via a forwarded agent socket.");

  script_tag(name:"affected", value:"OpenBSD OpenSSH prior to version 9.3p2.

  The following conditions needs to be met:

  - Exploitation requires the presence of specific libraries on the victim system.

  - Remote exploitation requires that the agent was forwarded to an attacker-controlled system.");

  script_tag(name:"solution", value:"Update to version 9.3p2 or later.");

  script_xref(name:"URL", value:"https://www.openssh.com/releasenotes.html#9.3p2");
  script_xref(name:"URL", value:"https://www.qualys.com/2023/07/19/cve-2023-38408/rce-openssh-forwarded-ssh-agent.txt");

  exit(0);
}
include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "9.3p2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3p2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
