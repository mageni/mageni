###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4137.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DSA 4137-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704137");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2018-1064", "CVE-2018-5748", "CVE-2018-6764");
  script_name("Debian Security Advisory DSA 4137-1 (libvirt - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-03-14 00:00:00 +0100 (Wed, 14 Mar 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4137.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"libvirt on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 1.2.9-9+deb8u5.

For the stable distribution (stretch), these problems have been fixed in
version 3.0.0-4+deb9u3.

We recommend that you upgrade your libvirt packages.

For the detailed security status of libvirt please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libvirt");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in Libvirt, a virtualisation
abstraction library:

CVE-2018-1064
Daniel Berrange discovered that the QEMU guest agent performed
insufficient validation of incoming data, which allows a privileged
user in the guest to exhaust resources on the virtualisation host,
resulting in denial of service.

CVE-2018-5748
Daniel Berrange and Peter Krempa that the QEMU monitor was suspectible
to denial of service by memory exhaustion. This was already fixed in
Debian stretch and only affects Debian jessie.

CVE-2018-6764
Pedro Sampaio discovered that LXC containers detected the hostname
insecurely. This only affects Debian stretch.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libnss-libvirt", ver:"3.0.0-4+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-clients", ver:"3.0.0-4+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-daemon", ver:"3.0.0-4+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-daemon-system", ver:"3.0.0-4+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-dev", ver:"3.0.0-4+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-doc", ver:"3.0.0-4+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-sanlock", ver:"3.0.0-4+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt0", ver:"3.0.0-4+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-bin", ver:"1.2.9-9+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-clients", ver:"1.2.9-9+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-daemon", ver:"1.2.9-9+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-daemon-system", ver:"1.2.9-9+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-dev", ver:"1.2.9-9+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-doc", ver:"1.2.9-9+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-sanlock", ver:"1.2.9-9+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt0", ver:"1.2.9-9+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt0-dbg", ver:"1.2.9-9+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}