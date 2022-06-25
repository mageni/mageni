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
  script_oid("1.3.6.1.4.1.25623.1.0.704989");
  script_version("2021-10-20T01:00:05+0000");
  script_cve_id("CVE-2021-41990", "CVE-2021-41991");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-20 10:23:51 +0000 (Wed, 20 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-20 01:00:05 +0000 (Wed, 20 Oct 2021)");
  script_name("Debian: Security Advisory for strongswan (DSA-4989-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4989.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4989-1");
  script_xref(name:"Advisory-ID", value:"DSA-4989-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'strongswan'
  package(s) announced via the DSA-4989-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Researchers at the United States of America National Security Agency (NSA)
identified two denial of services vulnerability in strongSwan, an IKE/IPsec
suite.

CVE-2021-41990
RSASSA-PSS signatures whose parameters define a very high salt length can
trigger an integer overflow that can lead to a segmentation fault.

Generating a signature that bypasses the padding check to trigger the crash
requires access to the private key that signed the certificate. However,
the certificate does not have to be trusted. Because the gmp and the
openssl plugins both check if a parsed certificate is self-signed (and the
signature is valid), this can e.g. be triggered by an unrelated
self-signed CA certificate sent by an initiator.

CVE-2021-41991
Once the in-memory certificate cache is full it tries to randomly replace
lesser used entries. Depending on the generated random value, this could
lead to an integer overflow that results in a double-dereference and a call
using out-of-bounds memory that most likely leads to a segmentation fault.

Remote code execution can't be ruled out completely, but attackers have no
control over the dereferenced memory, so it seems unlikely at this point.");

  script_tag(name:"affected", value:"'strongswan' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), these problems have been fixed
in version 5.7.2-1+deb10u1.

For the stable distribution (bullseye), these problems have been fixed in
version 5.9.1-1+deb11u1.

We recommend that you upgrade your strongswan packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"charon-cmd", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"charon-systemd", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcharon-extauth-plugins", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcharon-extra-plugins", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libstrongswan", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libstrongswan-extra-plugins", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libstrongswan-standard-plugins", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-charon", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-libcharon", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-nm", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-pki", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-scepclient", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-starter", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-swanctl", ver:"5.9.1-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"charon-cmd", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"charon-systemd", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcharon-extra-plugins", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libstrongswan", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libstrongswan-extra-plugins", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libstrongswan-standard-plugins", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-charon", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-libcharon", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-nm", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-pki", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-scepclient", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-starter", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-swanctl", ver:"5.7.2-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
