# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0109");
  script_tag(name:"creation_date", value:"2022-03-22 04:07:04 +0000 (Tue, 22 Mar 2022)");
  script_version("2022-03-22T04:07:04+0000");
  script_tag(name:"last_modification", value:"2022-03-22 11:26:02 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-03-22 04:07:04 +0000 (Tue, 22 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0109)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0109");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0109.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30185");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-March/010458.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SF6GP7Y7QBDPSDEMYQPWKSOXKRHILQVP/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'stunnel' package(s) announced via the MGASA-2022-0109 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 5.62 including new features and bugfixes:
Security bugfixes
- The 'redirect' option was fixed to properly handle unauthenticated
 requests (bsc#1182529).
- Fixed a double free with OpenSSL older than 1.1.0.
- Added hardening to systemd service (bsc#1181400).
New features
- Added new 'protocol = capwin' and 'protocol = capwinctrl'
 configuration file options.
- Added support for the new SSL_set_options() values.
- Added a bash completion script.
- New 'sessionResume' service-level option to allow or disallow
 session resumption
- Download fresh ca-certs.pem for each new release.
- New 'protocolHeader' service-level option to insert custom 'connect'
 protocol negotiation headers. This feature can be used to
 impersonate other software (e.g. web browsers).
- 'protocolHost' can also be used to control the client SMTP protocol
 negotiation HELO/EHLO value.
- Initial FIPS 3.0 support.
- Client-side 'protocol = ldap' support
Bugfixes
- Fixed a transfer() loop bug.
- Fixed reloading configuration with 'systemctl reload
 stunnel.service'.
- Fixed incorrect messages logged for OpenSSL errors.
- Fixed 'redirect' with 'protocol'. This combination is not supported
 by 'smtp', 'pop3' and 'imap' protocols.
- X.509v3 extensions required by modern versions of OpenSSL are added
 to generated self-signed test certificates.
- Fixed a tiny memory leak in configuration file reload error handling.
- Fixed engine initialization.
- FIPS TLS feature is reported when a provider or container is
 available, and not when FIPS control API is available.
- Fix configuration reload when compression is used
- Fix test suite fixed not to require external connectivity");

  script_tag(name:"affected", value:"'stunnel' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"stunnel", rpm:"stunnel~5.63~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
