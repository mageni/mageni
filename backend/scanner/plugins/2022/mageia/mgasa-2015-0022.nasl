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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0022");
  script_cve_id("CVE-2014-3569", "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-3575", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-15 02:29:00 +0000 (Wed, 15 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2015-0022)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0022");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0022.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14987");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv_20150108.txt");
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/mbs1/MDVSA-2015%3A019/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the MGASA-2015-0022 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A carefully crafted DTLS message can cause a segmentation fault in
OpenSSL due to a NULL pointer dereference. This could lead to a Denial
Of Service attack (CVE-2014-3571).

A memory leak can occur in the dtls1_buffer_record function under
certain conditions. In particular this could occur if an attacker
sent repeated DTLS records with the same sequence number but for the
next epoch. The memory leak could be exploited by an attacker in a
Denial of Service attack through memory exhaustion (CVE-2015-0206).

When openssl is built with the no-ssl3 option and a SSL v3 ClientHello
is received the ssl method would be set to NULL which could later
result in a NULL pointer dereference (CVE-2014-3569).

An OpenSSL client will accept a handshake using an ephemeral ECDH
ciphersuite using an ECDSA certificate if the server key exchange
message is omitted. This effectively removes forward secrecy from
the ciphersuite (CVE-2014-3572).

An OpenSSL client will accept the use of an RSA temporary key in
a non-export RSA key exchange ciphersuite. A server could present
a weak temporary key and downgrade the security of the session
(CVE-2015-0204).

An OpenSSL server will accept a DH certificate for client
authentication without the certificate verify message. This effectively
allows a client to authenticate without the use of a private key. This
only affects servers which trust a client certificate authority which
issues certificates containing DH keys: these are extremely rare and
hardly ever encountered (CVE-2015-0205).

OpenSSL accepts several non-DER-variations of certificate signature
algorithm and signature encodings. OpenSSL also does not enforce a
match between the signature algorithm between the signed and unsigned
portions of the certificate. By modifying the contents of the signature
algorithm or the encoding of the signature, it is possible to change
the certificate's fingerprint. This does not allow an attacker to
forge certificates, and does not affect certificate verification or
OpenSSL servers/clients in any other way. It also does not affect
common revocation mechanisms. Only custom applications that rely
on the uniqueness of the fingerprint (e.g. certificate blacklists)
may be affected (CVE-2014-8275).

Bignum squaring (BN_sqr) may produce incorrect results on some
platforms, including x86_64. This bug occurs at random with a very
low probability, and is not known to be exploitable in any way,
though its exact impact is difficult to determine (CVE-2014-3570).

The updated packages have been upgraded to the 1.0.1k version where
these security flaws have been fixed.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-devel", rpm:"lib64openssl-devel~1.0.1k~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-engines1.0.0", rpm:"lib64openssl-engines1.0.0~1.0.1k~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-static-devel", rpm:"lib64openssl-static-devel~1.0.1k~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl1.0.0", rpm:"lib64openssl1.0.0~1.0.1k~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~1.0.1k~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-engines1.0.0", rpm:"libopenssl-engines1.0.0~1.0.1k~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-static-devel", rpm:"libopenssl-static-devel~1.0.1k~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1.0.0", rpm:"libopenssl1.0.0~1.0.1k~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1k~1.mga4", rls:"MAGEIA4"))) {
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
