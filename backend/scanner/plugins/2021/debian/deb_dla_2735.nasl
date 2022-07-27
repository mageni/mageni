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
  script_oid("1.3.6.1.4.1.25623.1.0.892735");
  script_version("2021-08-13T11:44:16+0000");
  script_cve_id("CVE-2018-14662", "CVE-2018-16846", "CVE-2020-10753", "CVE-2020-1760", "CVE-2021-3524");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-08-16 10:18:22 +0000 (Mon, 16 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-13 09:50:27 +0000 (Fri, 13 Aug 2021)");
  script_name("Debian LTS: Security Advisory for ceph (DLA-2735-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/08/msg00013.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2735-1");
  script_xref(name:"Advisory-ID", value:"DLA-2735-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/921948");
  script_xref(name:"URL", value:"https://bugs.debian.org/921947");
  script_xref(name:"URL", value:"https://bugs.debian.org/956142");
  script_xref(name:"URL", value:"https://bugs.debian.org/975300");
  script_xref(name:"URL", value:"https://bugs.debian.org/988889");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph'
  package(s) announced via the DLA-2735-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Ceph, a distributed storage
and file system.

CVE-2018-14662

Authenticated ceph users with read only permissions could steal dm-crypt
encryption keys used in ceph disk encryption.

CVE-2018-16846

Authenticated ceph RGW users can cause a denial of service against OMAPs
holding bucket indices.

CVE-2020-10753

A flaw was found in the Red Hat Ceph Storage RadosGW (Ceph Object
Gateway).
The vulnerability is related to the injection of HTTP headers via a CORS
ExposeHeader tag. The newline character in the ExposeHeader tag in the
CORS configuration file generates a header injection in the response when
the CORS request is made.

CVE-2020-1760

A flaw was found in the Ceph Object Gateway, where it supports request
sent by an anonymous user in Amazon S3. This flaw could lead to potential
XSS attacks due to the lack of proper neutralization of untrusted input.

CVE-2021-3524

A flaw was found in the Red Hat Ceph Storage RadosGW (Ceph Object Gateway)
The vulnerability is related to the injection of HTTP headers via a CORS
ExposeHeader tag. The newline character in the ExposeHeader tag in the
CORS configuration file generates a header injection in the response when
the CORS request is made. In addition, the prior bug fix for CVE-2020-
10753 did not account for the use of \r as a header separator, thus a new
flaw has been created.");

  script_tag(name:"affected", value:"'ceph' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
10.2.11-2+deb9u1.

We recommend that you upgrade your ceph packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ceph-base", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ceph-fs-common", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ceph-fuse", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ceph-mds", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ceph-mon", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ceph-osd", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ceph-resource-agents", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ceph-test", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcephfs-dev", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcephfs-java", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcephfs-jni", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcephfs1", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librados-dev", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librados2", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libradosstriper-dev", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libradosstriper1", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librbd-dev", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librbd1", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librgw-dev", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librgw2", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-ceph", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-cephfs", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-rados", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-rbd", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"radosgw", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rbd-fuse", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rbd-mirror", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rbd-nbd", ver:"10.2.11-2+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
