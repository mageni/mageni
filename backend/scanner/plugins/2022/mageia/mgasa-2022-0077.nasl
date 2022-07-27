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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0077");
  script_cve_id("CVE-2021-44531", "CVE-2021-44532", "CVE-2021-44533", "CVE-2022-21824");
  script_tag(name:"creation_date", value:"2022-02-23 03:14:32 +0000 (Wed, 23 Feb 2022)");
  script_version("2022-02-24T11:31:07+0000");
  script_tag(name:"last_modification", value:"2022-02-24 11:31:07 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-02-23 03:14:32 +0000 (Wed, 23 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0077)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0077");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0077.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29872");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/jan-2022-security-releases/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v16.13.2/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IVGBTAQ3N7X3RJRMPD3QZXD76V4HSOEP/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/GUMNNY6AYZUDPQ3DHTM3JZST2C37ZYJB/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the MGASA-2022-0077 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Improper handling of URI Subject Alternative Names (Medium). Accepting
arbitrary Subject Alternative Name (SAN) types, unless a PKI is specifically
defined to use a particular SAN type, can result in bypassing
name-constrained intermediates. Node.js was accepting URI SAN types, which
PKIs are often not defined to use. Additionally, when a protocol allows URI
SANs, Node.js did not match the URI correctly. Versions of Node.js with the
fix for this disable the URI SAN type when checking a certificate against a
hostname. This behavior can be reverted through the --security-revert
command-line option. (CVE-2021-44531)

Node.js converts SANs (Subject Alternative Names) to a string format. It
uses this string to check peer certificates against hostnames when validating
connections. The string format was subject to an injection vulnerability when
name constraints were used within a certificate chain, allowing the bypass of
these name constraints. Versions of Node.js with the fix for this escape SANs
containing the problematic characters in order to prevent the injection. This
behavior can be reverted through the --security-revert command-line option.
(CVE-2021-44532)

Node.js did not handle multi-value Relative Distinguished Names correctly.
Attackers could craft certificate subjects containing a single-value Relative
Distinguished Name that would be interpreted as a multi-value Relative
Distinguished Name, for example, in order to inject a Common Name that would
allow bypassing the certificate subject verification. Affected versions of
Node.js do not accept multi-value Relative Distinguished Names and are thus
not vulnerable to such attacks themselves. However, third-party code that
uses node's ambiguous presentation of certificate subjects may be vulnerable.
(CVE-2021-44533)

Due to the formatting logic of the console.table() function it was not safe
to allow user controlled input to be passed to the properties parameter while
simultaneously passing a plain object with at least one property as the first
parameter, which could be __proto__. The prototype pollution has very limited
control, in that it only allows an empty string to be assigned to numerical
keys of the object prototype. Versions of Node.js with the fix for this use a
null prototype for the object these properties are being assigned to.
(CVE-2022-21824)");

  script_tag(name:"affected", value:"'nodejs' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~14.18.3~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~14.18.3~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~14.18.3~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~14.18.3~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm", rpm:"npm~6.14.15~1.14.18.3.2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-devel", rpm:"v8-devel~8.4.371.23.1.mga8~2.1.mga8", rls:"MAGEIA8"))) {
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
