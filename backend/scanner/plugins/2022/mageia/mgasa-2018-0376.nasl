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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0376");
  script_cve_id("CVE-2016-1000338", "CVE-2016-1000339", "CVE-2016-1000340", "CVE-2016-1000341", "CVE-2016-1000342", "CVE-2016-1000343", "CVE-2016-1000344", "CVE-2016-1000345", "CVE-2016-1000346", "CVE-2016-1000352", "CVE-2017-13098", "CVE-2018-1000180", "CVE-2018-1000613");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-14 15:20:00 +0000 (Fri, 14 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2018-0376)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0376");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0376.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22197");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4233");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-06/msg00085.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-07/msg00089.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bouncycastle' package(s) announced via the MGASA-2018-0376 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated bouncycastle packages fix security vulnerabilities:

Ensure full validation of ASN.1 encoding of signature on verification.
It was possible to inject extra elements in the sequence making up the
signature and still have it validate, which in some cases may have
allowed the introduction of 'invisible' data into a signed structure
(CVE-2016-1000338).

Prevent AESEngine key information leak via lookup table accesses
(CVE-2016-1000339).

Preventcarry propagation bugs in the implementation of squaring for
several raw math classes (CVE-2016-1000340).

DSA signature generation was vulnerable to timing attack. Where timings
can be closely observed for the generation of signatures may have allowed
an attacker to gain information about the signature's k value and
ultimately the private value as well (CVE-2016-1000341).

Ensure that ECDSA does fully validate ASN.1 encoding of signature on
verification. It was possible to inject extra elements in the sequence
making up the signature and still have it validate, which in some cases
may have allowed the introduction of 'invisible' data into a signed
structure (CVE-2016-1000342).

Prevent weak default settings for private DSA key pair generation
(CVE-2016-1000343).

Removed DHIES from the provider to disable the unsafe usage of ECB mode
(CVE-2016-1000344).

The DHIES/ECIES CBC mode was vulnerable to padding oracle attack. In an
environment where timings can be easily observed, it was possible with
enough observations to identify when the decryption is failing due to
padding (CVE-2016-1000345).

The other party DH public key was not fully validated. This could have
caused issues as invalid keys could be used to reveal details about the
other party's private key where static Diffie-Hellman is in use
(CVE-2016-1000346).

Remove ECIES from the provider to disable the unsafe usage of ECB mode
(CVE-2016-1000352).

BouncyCastle, when configured to use the JCE (Java Cryptography Extension)
for cryptographic functions, provided a weak Bleichenbacher oracle when
any TLS cipher suite using RSA key exchange was negotiated. An attacker
can recover the private key from a vulnerable application. This
vulnerability is referred to as 'ROBOT' (CVE-2017-13098).

It was discovered that the low-level interface to the RSA key pair
generator of Bouncy Castle (a Java implementation of cryptographic
algorithms) could perform less Miller-Rabin primality tests than expected
(CVE-2018-1000180).

Fix use of Externally-Controlled Input to Select Classes or Code
('Unsafe Reflection') (CVE-2018-1000613).");

  script_tag(name:"affected", value:"'bouncycastle' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle", rpm:"bouncycastle~1.60~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-javadoc", rpm:"bouncycastle-javadoc~1.60~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-mail", rpm:"bouncycastle-mail~1.60~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-pg", rpm:"bouncycastle-pg~1.60~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-pkix", rpm:"bouncycastle-pkix~1.60~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle-tls", rpm:"bouncycastle-tls~1.60~1.mga6", rls:"MAGEIA6"))) {
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
