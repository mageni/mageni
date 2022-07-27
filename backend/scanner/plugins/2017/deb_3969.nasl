###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_3969.nasl 14280 2019-03-18 14:50:45Z cfischer $
#
# Auto-generated from advisory DSA 3969-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703969");
  script_version("$Revision: 14280 $");
  script_cve_id("CVE-2017-10912", "CVE-2017-10913", "CVE-2017-10914", "CVE-2017-10915", "CVE-2017-10916", "CVE-2017-10917", "CVE-2017-10918", "CVE-2017-10919", "CVE-2017-10920", "CVE-2017-10921", "CVE-2017-10922", "CVE-2017-12135", "CVE-2017-12136", "CVE-2017-12137", "CVE-2017-12855");
  script_name("Debian Security Advisory DSA 3969-1 (xen - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:50:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-09-12 00:00:00 +0200 (Tue, 12 Sep 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3969.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");
  script_tag(name:"affected", value:"xen on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 4.4.1-9+deb8u10.

For the stable distribution (stretch), these problems have been fixed in
version 4.8.1-1+deb9u3.

We recommend that you upgrade your xen packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor:

CVE-2017-10912
Jann Horn discovered that incorrectly handling of page transfers might
result in privilege escalation.

CVE-2017-10913 / CVE-2017-10914
Jann Horn discovered that race conditions in grant handling might
result in information leaks or privilege escalation.

CVE-2017-10915
Andrew Cooper discovered that incorrect reference counting with
shadow paging might result in privilege escalation.

CVE-2017-10916
Andrew Cooper discovered an information leak in the handling
of the Memory Protection Extensions (MPX) and Protection
Key (PKU) CPU features. This only affects Debian stretch.

CVE-2017-10917
Ankur Arora discovered a NULL pointer dereference in event
polling, resulting in denial of service.

CVE-2017-10918
Julien Grall discovered that incorrect error handling in
physical-to-machine memory mappings may result in privilege
escalation, denial of service or an information leak.

CVE-2017-10919
Julien Grall discovered that incorrect handling of
virtual interrupt injection on ARM systems may result in
denial of service.

CVE-2017-10920 / CVE-2017-10921 / CVE-2017-10922
Jan Beulich discovered multiple places where reference
counting on grant table operations was incorrect, resulting
in potential privilege escalation.

CVE-2017-12135
Jan Beulich found multiple problems in the handling of
transitive grants which could result in denial of service
and potentially privilege escalation.

CVE-2017-12136
Ian Jackson discovered that race conditions in the allocator
for grant mappings may result in denial of service or privilege
escalation. This only affects Debian stretch.

CVE-2017-12137
Andrew Cooper discovered that incorrect validation of
grants may result in privilege escalation.

CVE-2017-12855
Jan Beulich discovered that incorrect grant status handling, thus
incorrectly informing the guest that the grant is no longer in use.

XSA-235 (no CVE yet)

Wei Liu discovered that incorrect locking of add-to-physmap
operations on ARM may result in denial of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libxen-4.4", ver:"4.4.1-9+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxen-dev", ver:"4.4.1-9+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.4.1-9+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.4-amd64", ver:"4.4.1-9+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.4-arm64", ver:"4.4.1-9+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.4-armhf", ver:"4.4.1-9+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.4.1-9+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.4.1-9+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.4.1-9+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-utils-4.4", ver:"4.4.1-9+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.4.1-9+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.4.1-9+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxen-4.8", ver:"4.8.1-1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxen-dev", ver:"4.8.1-1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.8.1-1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.8-amd64", ver:"4.8.1-1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.8-arm64", ver:"4.8.1-1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.8-armhf", ver:"4.8.1-1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.8.1-1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.8.1-1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.8.1-1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-utils-4.8", ver:"4.8.1-1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.8.1-1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.8.1-1+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}