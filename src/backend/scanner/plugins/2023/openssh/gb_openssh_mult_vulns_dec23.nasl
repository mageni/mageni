# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118572");
  script_version("2024-01-05T16:09:35+0000");
  script_tag(name:"last_modification", value:"2024-01-05 16:09:35 +0000 (Fri, 05 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-12-20 08:49:28 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-03 19:40:00 +0000 (Wed, 03 Jan 2024)");

  script_cve_id("CVE-2023-48795", "CVE-2023-51384", "CVE-2023-51385");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenBSD OpenSSH < 9.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"summary", value:"OpenBSD OpenSSH is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-48795: The SSH transport protocol with certain OpenSSH extensions allows remote
  attackers to bypass integrity checks such that some packets are omitted (from the extension
  negotiation message), and a client and server may consequently end up with a connection for which
  some security features have been downgraded or disabled, aka a 'Terrapin attack'.

  - CVE-2023-51384: In ssh-agent certain destination constraints can be incompletely applied. When
  destination constraints are specified during addition of PKCS#11-hosted private keys, these
  constraints are only applied to the first key, even if a PKCS#11 token returns multiple keys.

  - CVE-2023-51385: OS command injection might occur if a user name or host name has shell
  metacharacters, and this name is referenced by an expansion token in certain situations. For
  example, an untrusted Git repository can have a submodule with shell metacharacters in a user
  name or host name.");

  script_tag(name:"affected", value:"OpenBSD OpenSSH prior to version 9.6.");

  script_tag(name:"solution", value:"Update to version 9.6 or later.");

  script_xref(name:"URL", value:"https://www.openssh.com/txt/release-9.6");
  script_xref(name:"URL", value:"https://terrapin-attack.com");
  script_xref(name:"URL", value:"https://vin01.github.io/piptagole/ssh/security/openssh/libssh/remote-code-execution/2023/12/20/openssh-proxycommand-libssh-rce.html");

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

if (version_is_less(version: version, test_version: "9.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
