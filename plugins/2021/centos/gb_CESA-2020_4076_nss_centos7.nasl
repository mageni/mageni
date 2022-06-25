# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883343");
  script_version("2021-05-10T06:49:03+0000");
  script_cve_id("CVE-2019-11719", "CVE-2019-11727", "CVE-2019-11756", "CVE-2019-17006", "CVE-2019-17023", "CVE-2020-6829", "CVE-2020-12400", "CVE-2020-12401", "CVE-2020-12402", "CVE-2020-12403");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-05-10 10:15:03 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-01 03:00:42 +0000 (Sat, 01 May 2021)");
  script_name("CentOS: Security Advisory for nss (CESA-2020:4076)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2020:4076");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-April/048312.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss'
  package(s) announced via the CESA-2020:4076 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Network Security Services (NSS) is a set of libraries designed to support
the cross-platform development of security-enabled client and server
applications.

Netscape Portable Runtime (NSPR) provides platform independence for non-GUI
operating system facilities.

The following packages have been upgraded to a later upstream version: nss
(3.53.1), nss-softokn (3.53.1), nss-util (3.53.1), nspr (4.25.0).
(BZ#1804262, BZ#1804264, BZ#1804271, BZ#1804273)

Security Fix(es):

  * nss: Out-of-bounds read when importing curve25519 private key
(CVE-2019-11719)

  * nss: Use-after-free in sftk_FreeSession due to improper refcounting
(CVE-2019-11756)

  * nss: Check length of inputs for cryptographic primitives (CVE-2019-17006)

  * nss: Side channel attack on ECDSA signature generation (CVE-2020-6829)

  * nss: P-384 and P-521 implementation uses a side-channel vulnerable
modular inversion function (CVE-2020-12400)

  * nss: ECDSA timing attack mitigation bypass (CVE-2020-12401)

  * nss: Side channel vulnerabilities during RSA key generation
(CVE-2020-12402)

  * nss: CHACHA20-POLY1305 decryption with undersized tag leads to
out-of-bounds read (CVE-2020-12403)

  * nss: PKCS#1 v1.5 signatures can be used for TLS 1.3 (CVE-2019-11727)

  * nss: TLS 1.3 HelloRetryRequest downgrade request sets client into invalid
state (CVE-2019-17023)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * Memory leak: libcurl leaks 120 bytes on each connection (BZ#1688958)

  * NSS does not set downgrade sentinel in ServerHello.random for TLS 1.0 and
TLS 1.1 (BZ#1712924)

  * Make TLS 1.3 work in FIPS mode (BZ#1724251)

  * Name Constraints validation: CN treated as DNS name even when
syntactically invalid as DNS name (BZ#1737910)

  * x25519 allowed in FIPS mode (BZ#1754518)

  * When NSS_SDB_USE_CACHE not set, after curl access https, dentry increase
but never released - consider alternative algorithm for benchmarking ACCESS
call in sdb_measureAccess (BZ#1779325)

  * Running ipa-backup continuously causes httpd to crash and makes it
irrecoverable (BZ#1804015)

  * nss needs to comply to the new SP800-56A rev 3 requirements (BZ#1857308)

  * KDF-self-tests-induced changes for nss in RHEL 7.9 (BZ#1870885)");

  script_tag(name:"affected", value:"'nss' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.53.1~7.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.53.1~7.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.53.1~7.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.53.1~7.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.53.1~7.el7_9", rls:"CentOS7"))) {
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