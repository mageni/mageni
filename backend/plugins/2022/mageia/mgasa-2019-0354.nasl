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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0354");
  script_cve_id("CVE-2019-1543", "CVE-2019-1547", "CVE-2019-1563");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 20:29:00 +0000 (Mon, 03 Jun 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0354)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0354");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0354.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24888");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20190306.txt");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4475");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20190910.txt");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4540");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'compat-openssl10, openssl' package(s) announced via the MGASA-2019-0354 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

ChaCha20-Poly1305 is an AEAD cipher, and requires a unique nonce input
for every encryption operation. RFC 7539 specifies that the nonce value
(IV) should be 96 bits (12 bytes). OpenSSL allows a variable nonce length
and front pads the nonce with 0 bytes if it is less than 12 bytes. However
it also incorrectly allows a nonce to be set of up to 16 bytes. In this
case only the last 12 bytes are significant and any additional leading
bytes are ignored. It is a requirement of using this cipher that nonce
values are unique. Messages encrypted using a reused nonce value are
susceptible to serious confidentiality and integrity attacks. If an
application changes the default nonce length to be longer than 12 bytes
and then makes a change to the leading bytes of the nonce expecting the
new value to be a new unique nonce then such an application could
inadvertently encrypt messages with a reused nonce. Additionally the
ignored bytes in a long nonce are not covered by the integrity guarantee
of this cipher. Any application that relies on the integrity of these
ignored leading bytes of a long nonce may be further affected. Any OpenSSL
internal use of this cipher, including in SSL/TLS, is safe because no such
use sets such a long nonce value. However user applications that use this
cipher directly and set a non-default nonce length to be longer than 12
bytes may be vulnerable. (CVE-2019-1543)

Normally in OpenSSL EC groups always have a co-factor present and this is
used in side channel resistant code paths. However, in some cases, it is
possible to construct a group using explicit parameters (instead of using
a named curve). In those cases it is possible that such a group does not
have the cofactor present. This can occur even where all the parameters
match a known named curve. If such a curve is used then OpenSSL falls back
to non-side channel resistant code paths which may result in full key
recovery during an ECDSA signature operation. In order to be vulnerable an
attacker would have to have the ability to time the creation of a large
number of signatures where explicit parameters with no co-factor present
are in use by an application using libcrypto. For the avoidance of doubt
libssl is not vulnerable because explicit parameters are never used.
(CVE-2019-1547)

In situations where an attacker receives automated notification of the
success or failure of a decryption attempt an attacker, after sending a
very large number of messages to be decrypted, can recover a CMS/PKCS7
transported encryption key or decrypt any RSA encrypted message that was
encrypted with the public RSA key, using a Bleichenbacher padding oracle
attack. Applications are not affected if they use a certificate together
with the private RSA key to the CMS_decrypt or PKCS7_decrypt functions
to select the correct recipient info to decrypt. (CVE-2019-1563)");

  script_tag(name:"affected", value:"'compat-openssl10, openssl' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"compat-openssl10", rpm:"compat-openssl10~1.0.2t~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64compat-openssl10-devel", rpm:"lib64compat-openssl10-devel~1.0.2t~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64compat-openssl10_1.0.0", rpm:"lib64compat-openssl10_1.0.0~1.0.2t~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-devel", rpm:"lib64openssl-devel~1.1.0l~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-static-devel", rpm:"lib64openssl-static-devel~1.1.0l~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl1.1", rpm:"lib64openssl1.1~1.1.0l~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcompat-openssl10-devel", rpm:"libcompat-openssl10-devel~1.0.2t~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcompat-openssl10_1.0.0", rpm:"libcompat-openssl10_1.0.0~1.0.2t~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~1.1.0l~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-static-devel", rpm:"libopenssl-static-devel~1.1.0l~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1.1", rpm:"libopenssl1.1~1.1.0l~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.1.0l~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.1.0l~1.mga7", rls:"MAGEIA7"))) {
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
