###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1261.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1261-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891261");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376", "CVE-2017-12377", "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1261-1] clamav security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-31 00:00:00 +0100 (Wed, 31 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/01/msg00035.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"clamav on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
0.99.2+dfsg-0+deb7u4.

We recommend that you upgrade your clamav packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in clamav, the ClamAV
AntiVirus toolkit for Unix. Effects range from denial of service to
potential arbitrary code execution. Additionally, this version fixes
a longstanding issue that has recently resurfaced whereby a malformed
virus signature database can cause an application crash and denial of
service.

CVE-2017-12374

ClamAV has a use-after-free condition arising from a lack of input
validation. A remote attacker could exploit this vulnerability with
a crafted email message to cause a denial of service.

CVE-2017-12375

ClamAV has a buffer overflow vulnerability arising from a lack of
input validation. An unauthenticated remote attacker could send a
crafted email message to the affected device, triggering a buffer
overflow and potentially a denial of service when the malicious
message is scanned.

CVE-2017-12376

ClamAV has a buffer overflow vulnerability arising from improper
input validation when handling Portable Document Format (PDF) files.
An unauthenticated remote attacker could send a crafted PDF file to
the affected device, triggering a buffer overflow and potentially a
denial of service or arbitrary code execution when the malicious
file is scanned.

CVE-2017-12377

ClamAV has a heap overflow vulnerability arising from improper input
validation when handling mew packets. An attacker could exploit this
by sending a crafted message to the affected device, triggering a
denial of service or possible arbitrary code execution when the
malicious file is scanned.

CVE-2017-12378

ClamAV has a buffer overread vulnerability arising from improper
input validation when handling tape archive (TAR) files. An
unauthenticated remote attacker could send a crafted TAR file to
the affected device, triggering a buffer overread and potentially a
denial of service when the malicious file is scanned.

CVE-2017-12379

ClamAV has a buffer overflow vulnerability arising from improper
input validation in the message parsing function. An unauthenticated
remote attacker could send a crafted email message to the affected
device, triggering a buffer overflow and potentially a denial of
service or arbitrary code execution when the malicious message is
scanned.

CVE-2017-12380

ClamAV has a NULL dereference vulnerability arising from improper
input validation in the message parsing function. An unauthenticated
remote attacker could send a crafted email message to the affected
device, triggering a NULL pointer dereference, which may result in a
denial of service.

Debian Bug #824196

A malformed virus signature database could cause an application
crash and denial of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"clamav", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-base", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-docs", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-milter", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libclamav7", ver:"0.99.2+dfsg-0+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}