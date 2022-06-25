# OpenVAS Vulnerability Test
# $Id: deb_3688.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3688-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703688");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2015-4000", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7575",
                  "CVE-2016-1938", "CVE-2016-1950", "CVE-2016-1978", "CVE-2016-1979",
                  "CVE-2016-2834");
  script_name("Debian Security Advisory DSA 3688-1 (nss - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-10-05 00:00:00 +0200 (Wed, 05 Oct 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3688.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"nss on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 2:3.26-1+debu8u1.

For the unstable distribution (sid), these problems have been fixed in
version 2:3.23-1.

We recommend that you upgrade your nss packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered
in NSS, the cryptography library developed by the Mozilla project.

CVE-2015-4000
David Adrian et al. reported that it may be feasible to attack
Diffie-Hellman-based cipher suites in certain circumstances,
compromising the confidentiality and integrity of data encrypted
with Transport Layer Security (TLS).

CVE-2015-7181 CVE-2015-7182 CVE-2016-1950
Tyson Smith, David Keeler, and Francis Gabriel discovered
heap-based buffer overflows in the ASN.1 DER parser, potentially
leading to arbitrary code execution.

CVE-2015-7575
Karthikeyan Bhargavan discovered that TLS client implementation
accepted MD5-based signatures for TLS 1.2 connections with forward
secrecy, weakening the intended security strength of TLS
connections.

CVE-2016-1938
Hanno Boeck discovered that NSS miscomputed the result of integer
division for certain inputs. This could weaken the cryptographic
protections provided by NSS. However, NSS implements RSA-CRT leak
hardening, so RSA private keys are not directly disclosed by this
issue.

CVE-2016-1978
Eric Rescorla discovered a use-after-free vulnerability in the
implementation of ECDH-based TLS handshakes, with unknown
consequences.

CVE-2016-1979
Tim Taubert discovered a use-after-free vulnerability in ASN.1 DER
processing, with application-specific impact.

CVE-2016-2834
Tyson Smith and Jed Davis discovered unspecified memory-safety
bugs in NSS.

In addition, the NSS library did not ignore environment variables in
processes which underwent a SUID/SGID/AT_SECURE transition at process
start. In certain system configurations, this allowed local users to
escalate their privileges.

This update contains further correctness and stability fixes without
immediate security impact.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libnss3:amd64", ver:"2:3.26-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss3:i386", ver:"2:3.26-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libnss3-1d:amd64", ver:"2:3.26-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss3-1d:i386", ver:"2:3.26-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libnss3-dbg:amd64", ver:"2:3.26-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss3-dbg:i386", ver:"2:3.26-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libnss3-dev", ver:"2:3.26-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libnss3-tools", ver:"2:3.26-1+debu8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}