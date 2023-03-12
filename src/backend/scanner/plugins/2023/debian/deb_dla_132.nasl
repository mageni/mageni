# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.132");
  script_cve_id("CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DLA-132)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-132");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-132");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DLA-132 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in OpenSSL, a Secure Sockets Layer toolkit. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2014-3570

Pieter Wuille of Blockstream reported that the bignum squaring (BN_sqr) may produce incorrect results on some platforms, which might make it easier for remote attackers to defeat cryptographic protection mechanisms.

CVE-2014-3571

Markus Stenberg of Cisco Systems, Inc. reported that a carefully crafted DTLS message can cause a segmentation fault in OpenSSL due to a NULL pointer dereference. A remote attacker could use this flaw to mount a denial of service attack.

CVE-2014-3572

Karthikeyan Bhargavan of the PROSECCO team at INRIA reported that an OpenSSL client would accept a handshake using an ephemeral ECDH ciphersuite if the server key exchange message is omitted. This allows remote SSL servers to conduct ECDHE-to-ECDH downgrade attacks and trigger a loss of forward secrecy.

CVE-2014-8275

Antti Karjalainen and Tuomo Untinen of the Codenomicon CROSS project and Konrad Kraszewski of Google reported various certificate fingerprint issues, which allow remote attackers to defeat a fingerprint-based certificate-blacklist protection mechanism.

CVE-2015-0204

Karthikeyan Bhargavan of the PROSECCO team at INRIA reported that an OpenSSL client will accept the use of an ephemeral RSA key in a non-export RSA key exchange ciphersuite, violating the TLS standard. This allows remote SSL servers to downgrade the security of the session.

For Debian 6 Squeeze, these issues have been fixed in openssl version 0.9.8o-4squeeze19");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8o-4squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8o-4squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8o-4squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8o-4squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"0.9.8o-4squeeze19", rls:"DEB6"))) {
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
