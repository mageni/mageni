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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0246");
  script_cve_id("CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792", "CVE-2015-4000");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-15 02:29:00 +0000 (Wed, 15 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2015-0246)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0246");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0246.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16071");
  script_xref(name:"URL", value:"http://openssl.org/news/secadv_20150611.txt");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2639-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the MGASA-2015-0246 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in the TLS protocol allows a man-in-the-middle attacker to
downgrade vulnerable TLS connections using ephemeral Diffie-Hellman key
exchange to 512-bit export-grade cryptography. This vulnerability is known
as Logjam (CVE-2015-4000).

When processing an ECParameters structure OpenSSL enters an infinite loop if
the curve specified is over a specially malformed binary polynomial field.
This can be used to perform denial of service against any system which
processes public keys, certificate requests or certificates. This includes
TLS clients and TLS servers with client authentication enabled
(CVE-2015-1788).

X509_cmp_time does not properly check the length of the ASN1_TIME string and
can read a few bytes out of bounds. In addition, X509_cmp_time accepts an
arbitrary number of fractional seconds in the time string. An attacker can
use this to craft malformed certificates and CRLs of various sizes and
potentially cause a segmentation fault, resulting in a DoS on applications
that verify certificates or CRLs. TLS clients that verify CRLs are affected.
TLS clients and servers with client authentication enabled may be affected
if they use custom verification callbacks (CVE-2015-1789).

The PKCS#7 parsing code does not handle missing inner EncryptedContent
correctly. An attacker can craft malformed ASN.1-encoded PKCS#7 blobs
with missing content and trigger a NULL pointer dereference on parsing
(CVE-2015-1790).

If a NewSessionTicket is received by a multi-threaded client when attempting
to reuse a previous ticket then a race condition can occur potentially
leading to a double free of the ticket data (CVE-2015-1791).

When verifying a signedData message the CMS code can enter an infinite loop
if presented with an unknown hash function OID. This can be used to perform
denial of service against any system which verifies signedData messages
using the CMS code (CVE-2015-1792).");

  script_tag(name:"affected", value:"'openssl' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-devel", rpm:"lib64openssl-devel~1.0.1o~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-engines1.0.0", rpm:"lib64openssl-engines1.0.0~1.0.1o~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-static-devel", rpm:"lib64openssl-static-devel~1.0.1o~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl1.0.0", rpm:"lib64openssl1.0.0~1.0.1o~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~1.0.1o~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-engines1.0.0", rpm:"libopenssl-engines1.0.0~1.0.1o~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-static-devel", rpm:"libopenssl-static-devel~1.0.1o~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1.0.0", rpm:"libopenssl1.0.0~1.0.1o~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1o~1.mga4", rls:"MAGEIA4"))) {
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
