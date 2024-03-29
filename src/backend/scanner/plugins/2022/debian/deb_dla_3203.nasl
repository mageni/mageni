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
  script_oid("1.3.6.1.4.1.25623.1.0.893203");
  script_version("2022-11-24T10:18:54+0000");
  script_cve_id("CVE-2021-3618", "CVE-2022-41741", "CVE-2022-41742");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-11-24 10:18:54 +0000 (Thu, 24 Nov 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 20:46:00 +0000 (Mon, 04 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-11-24 02:00:16 +0000 (Thu, 24 Nov 2022)");
  script_name("Debian LTS: Security Advisory for nginx (DLA-3203-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/11/msg00031.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3203-1");
  script_xref(name:"Advisory-ID", value:"DLA-3203-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/991328");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx'
  package(s) announced via the DLA-3203-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that parsing errors in the mp4 module of Nginx, a
high-performance web and reverse proxy server, could result in denial
of service, memory disclosure or potentially the execution of arbitrary
code when processing a malformed mp4 file.

This module is only enabled in the nginx-extras binary package.

In addition the following vulnerability has been fixed.

CVE-2021-3618

ALPACA is an application layer protocol content confusion attack,
exploiting TLS servers implementing different protocols but using
compatible certificates, such as multi-domain or wildcard certificates.
A MiTM attacker having access to victim's traffic at the TCP/IP layer can
redirect traffic from one subdomain to another, resulting in a valid TLS
session. This breaks the authentication of TLS and cross-protocol attacks
may be possible where the behavior of one protocol service may compromise");

  script_tag(name:"affected", value:"'nginx' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1.14.2-2+deb10u5.

We recommend that you upgrade your nginx packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-auth-pam", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-cache-purge", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-dav-ext", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-echo", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-fancyindex", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-geoip", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-headers-more-filter", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-image-filter", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-lua", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-ndk", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-perl", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-subs-filter", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-uploadprogress", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-upstream-fair", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-http-xslt-filter", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-mail", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-nchan", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-rtmp", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnginx-mod-stream", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nginx", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nginx-common", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nginx-doc", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nginx-extras", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nginx-full", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nginx-light", ver:"1.14.2-2+deb10u5", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
