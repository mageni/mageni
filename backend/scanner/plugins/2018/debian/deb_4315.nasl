###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4315.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DSA 4315-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704315");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2018-16056", "CVE-2018-16057", "CVE-2018-16058");
  script_name("Debian Security Advisory DSA 4315-1 (wireshark - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-10-12 00:00:00 +0200 (Fri, 12 Oct 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4315.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"wireshark on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 2.6.3-1~deb9u1. This update upgrades Wireshark to the 2.6.x
release branch, future security upgrades will be based on this series.

We recommend that you upgrade your wireshark packages.

For the detailed security status of wireshark please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wireshark");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in Wireshark, a network
protocol analyzer which could result in denial of service or the
execution of arbitrary code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libwireshark-data", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwireshark-dev", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwiretap-dev", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwsutil-dev", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tshark", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wireshark", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wireshark-common", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wireshark-dev", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wireshark-doc", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wireshark-gtk", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wireshark-qt", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}

# nb: For some reason libwireshark8, libwiretap6, libwscodecs1 and libwsutil7 are still at 2.2.6+g32dac6a-2+deb9u3 in stretch.
# Keep those commented out for now to avoid possible FPs...
#if((res = isdpkgvuln(pkg:"libwireshark8", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
#    report += res;
#}
#if((res = isdpkgvuln(pkg:"libwiretap6", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
#    report += res;
#}
#if((res = isdpkgvuln(pkg:"libwscodecs1", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
#    report += res;
#}
#if((res = isdpkgvuln(pkg:"libwsutil7", ver:"2.6.3-1~deb9u1", rls:"DEB9")) != NULL) {
#    report += res;
#}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}