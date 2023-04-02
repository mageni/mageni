# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104635");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-16 07:20:41 +0000 (Thu, 16 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenBSD OpenSSH < 9.3 Unspecified Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"summary", value:"OpenBSD OpenSSH is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ssh(1): Portable OpenSSH provides an implementation of the
  getrrsetbyname(3) function if the standard library does not provide it, for use by the
  VerifyHostKeyDNS feature. A specifically crafted DNS response could cause this function to perform
  an out-of-bounds read of adjacent stack data, but this condition does not appear to be exploitable
  beyond denial-of-service to the ssh(1) client.

  The getrrsetbyname(3) replacement is only included if the system's standard library lacks this
  function and portable OpenSSH was not compiled with the ldns library (--with-ldns).
  getrrsetbyname(3) is only invoked if using VerifyHostKeyDNS to fetch SSHFP records.This problem
  was found by the Coverity static analyzer.");

  script_tag(name:"affected", value:"OpenBSD OpenSSH prior to version 9.3.");

  script_tag(name:"solution", value:"Update to version 9.3 or later.");

  script_xref(name:"URL", value:"https://www.openssh.com/releasenotes.html#9.3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/03/15/8");

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

if (version_is_less(version: version, test_version: "9.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
