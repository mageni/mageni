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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0369");
  script_cve_id("CVE-2021-27918", "CVE-2021-31525", "CVE-2021-33195", "CVE-2021-33196", "CVE-2021-33197", "CVE-2021-33198", "CVE-2021-34558");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-18 14:34:00 +0000 (Thu, 18 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0369)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0369");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0369.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29037");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EXHOWUQKHNS4LEJ2GTYWY2EEAYVCKECW/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4PG5AXR4LXEWYU5DHYEVESCXWKO3HFHO/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/QLUQXBCOPWP72ZSS3SM3CTURM7XOYALQ/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AKQH4LHYIFOWBEGMGHD7S7TTV7JL4U7W/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OZJXXUXBI66VV2PXRNAWN4MCE3AOHNBA/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang' package(s) announced via the MGASA-2021-0369 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"encoding/xml in Go before 1.15.9 and 1.16.x before 1.16.1 has an infinite loop
if a custom TokenReader (for xml.NewTokenDecoder) returns EOF in the middle of
an element. This can occur in the Decode, DecodeElement, or Skip method
(CVE-2021-27918).

net/http in Go before 1.15.12 and 1.16.x before 1.16.4 allows remote attackers
to cause a denial of service (panic) via a large header to ReadRequest or
ReadResponse. Server, Transport, and Client can each be affected in some
configurations (CVE-2021-31525).

A security issue has been found in Go before version 1.16.5. The LookupCNAME,
LookupSRV, LookupMX, LookupNS, and LookupAddr functions in net, and their
respective methods on the Resolver type may return arbitrary values retrieved
from DNS which do not follow the established RFC 1035 rules for domain names.
If these names are used without further sanitization, for instance unsafely
included in HTML, they may allow for injection of unexpected content. Note
that LookupTXT may still return arbitrary values that could require
sanitization before further use (CVE-2021-33195).

A security issue has been found in Go. Due to a pre-allocation optimization in
zip.NewReader, a malformed archive which indicates it has a significant number
of files can cause either a panic or memory exhaustion (CVE-2021-33196).

ReverseProxy fails to delete the Connection headers (as well as other legacy
hop-by-hop headers, which however per RFC 7230 need to also be specified in
Connection) if there are multiple ones and the first is empty, due to an
incorrect Get(h) == '' check. This can lead to a security issue if the proxy
is adding an important header, like X-Forwarded-For, and is sitting in front
of another proxy which can be instructed by an attacker to drop that header as
a hop-by-hop header (CVE-2021-33197).

A security issue has been found in Go before version 1.16.5. The SetString and
UnmarshalText methods of math/big.Rat may cause a panic or an unrecoverable
fatal error if passed inputs with very large exponents (CVE-2021-33198).

The crypto/tls package of Go through 1.16.5 does not properly assert that the
type of public key in an X.509 certificate matches the expected type when
doing a RSA based key exchange, allowing a malicious TLS server to cause a TLS
client to panic (CVE-2021-34558).");

  script_tag(name:"affected", value:"'golang' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.15.14~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.15.14~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.15.14~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.15.14~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.15.14~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.15.14~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.15.14~1.mga8", rls:"MAGEIA8"))) {
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
