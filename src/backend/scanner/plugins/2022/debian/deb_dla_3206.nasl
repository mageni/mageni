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
  script_oid("1.3.6.1.4.1.25623.1.0.893206");
  script_version("2022-11-28T09:49:27+0000");
  script_cve_id("CVE-2019-14870", "CVE-2021-3671", "CVE-2021-44758", "CVE-2022-3437", "CVE-2022-41916", "CVE-2022-42898", "CVE-2022-44640");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-11-28 09:49:27 +0000 (Mon, 28 Nov 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-29 13:15:00 +0000 (Sat, 29 May 2021)");
  script_tag(name:"creation_date", value:"2022-11-27 02:00:15 +0000 (Sun, 27 Nov 2022)");
  script_name("Debian LTS: Security Advisory for heimdal (DLA-3206-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/11/msg00034.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3206-1");
  script_xref(name:"Advisory-ID", value:"DLA-3206-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/946786");
  script_xref(name:"URL", value:"https://bugs.debian.org/996586");
  script_xref(name:"URL", value:"https://bugs.debian.org/1024187");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'heimdal'
  package(s) announced via the DLA-3206-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities were discovered in heimdal, an
implementation of the Kerberos 5 authentication protocol, which may
result in denial of service, information disclosure, or remote code
execution.

CVE-2019-14870

Isaac Boukris reported that the Heimdal KDC before 7.7.1 does not
apply delegation_not_allowed (aka not-delegated) user attributes for
S4U2Self. Instead the forwardable flag is set even if the
impersonated client has the not-delegated flag set.

CVE-2021-3671

Joseph Sutton discovered that the Heimdal KDC before 7.7.1 does not
check for missing missing sname in TGS-REQ (Ticket Granting Server -
Request) before before dereferencing. An authenticated user could
use this flaw to crash the KDC.

CVE-2021-44758

It was discovered that Heimdal is prone to a NULL dereference in
acceptors when the initial SPNEGO token has no acceptable
mechanisms, which may result in denial of service for a server
application that uses the Simple and Protected GSSAPI Negotiation
Mechanism (SPNEGO).

CVE-2022-3437

Evgeny Legerov reported that the DES and Triple-DES decryption
routines in the Heimdal GSSAPI library before 7.7.1 were prone to
buffer overflow on malloc() allocated memory when presented with a
maliciously small packet. In addition, the Triple-DES and RC4
(arcfour) decryption routine were prone to non-constant time leaks,
which could potentially yield to a leak of secret key material when
using these ciphers.

CVE-2022-41916

It was discovered that Heimdal's PKI certificate validation library
before 7.7.1 can under some circumstances perform an out-of-bounds
memory access when normalizing Unicode, which may result in denial
of service.

CVE-2022-42898

Greg Hudson discovered an integer multiplication overflow in the
Privilege Attribute Certificate (PAC) parsing routine, which may
result in denial of service for Heimdal KDCs and possibly Heimdal
servers (e.g., via GSS-API) on 32-bit systems.

CVE-2022-44640

Douglas Bagnall and the Heimdal maintainers independently discovered
that Heimdal's ASN.1 compiler before 7.7.1 generates code that
allows specially crafted DER encodings of CHOICEs to invoke the
wrong free() function on the decoded structure upon decode error,
which may result in remote code execution in the Heimdal KDC and
possibly the Kerberos client, the X.509 library, and other
components as well.");

  script_tag(name:"affected", value:"'heimdal' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
7.5.0+dfsg-3+deb10u1.

We recommend that you upgrade your heimdal packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-dev", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-docs", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-kcm", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-kdc", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-multidev", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libasn1-8-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libhcrypto4-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libhdb9-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libheimbase1-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libheimntlm0-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libhx509-5-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkadm5clnt7-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkadm5srv8-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkafs0-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkdc2-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libotp0-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libroken18-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsl0-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwind0-heimdal", ver:"7.5.0+dfsg-3+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
