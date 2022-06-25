# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891715");
  script_version("$Revision: 14297 $");
  script_cve_id("CVE-2017-18249", "CVE-2018-1128", "CVE-2018-1129", "CVE-2018-12896", "CVE-2018-13053",
                "CVE-2018-13096", "CVE-2018-13097", "CVE-2018-13100", "CVE-2018-13406", "CVE-2018-14610",
                "CVE-2018-14611", "CVE-2018-14612", "CVE-2018-14613", "CVE-2018-14614", "CVE-2018-14616",
                "CVE-2018-15471", "CVE-2018-16862", "CVE-2018-17972", "CVE-2018-18281", "CVE-2018-18690",
                "CVE-2018-18710", "CVE-2018-19407", "CVE-2018-3639", "CVE-2018-5391", "CVE-2018-5848",
                "CVE-2018-6554");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1715-1] linux-4.9 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 08:35:21 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-19 00:00:00 +0100 (Tue, 19 Mar 2019)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00017.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"linux-4.9 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4.9.144-3.1~deb8u1. This version also includes fixes for Debian bugs
#890034, #896911, #907581, #915229, #915231 and other fixes
included in upstream stable updates.

We recommend that you upgrade your linux-4.9 packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-18249

    A race condition was discovered in the disk space allocator of
    F2FS. A user with access to an F2FS volume could use this to cause
    a denial of service or other security impact.

CVE-2018-1128, CVE-2018-1129

    The cephx authentication protocol used by Ceph was susceptible to
    replay attacks, and calculated signatures incorrectly. These
    vulnerabilities in the server required changes to authentication
    that are incompatible with existing clients. The kernel's client
    code has now been updated to be compatible with the fixed server.

  Description truncated. Please see the references for more information.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"linux-compiler-gcc-4.9-arm", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-686", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-686-pae", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-amd64", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-armel", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-armhf", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-i386", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-amd64", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-armmp", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-armmp-lpae", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-common", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-common-rt", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-marvell", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-rt-686-pae", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-rt-amd64", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-686", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-686-pae", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-amd64", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-armel", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-armhf", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-i386", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-amd64", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-armmp", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-armmp-lpae", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-common", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-common-rt", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-marvell", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-rt-686-pae", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-rt-amd64", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-686", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-686-pae", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-686-pae-dbg", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-amd64", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-amd64-dbg", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-armmp", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-armmp-lpae", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-marvell", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-686-pae", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-amd64", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-amd64-dbg", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-686", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-686-pae", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-686-pae-dbg", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-amd64", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-amd64-dbg", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-armmp", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-armmp-lpae", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-marvell", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-686-pae", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-686-pae-dbg", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-amd64", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-amd64-dbg", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.7", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.8", ver:"4.9.144-3.1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}