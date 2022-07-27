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
  script_oid("1.3.6.1.4.1.25623.1.0.892927");
  script_version("2022-02-21T14:09:09+0000");
  script_cve_id("CVE-2020-10108", "CVE-2020-10109", "CVE-2022-21712");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-22 11:21:00 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2022-02-20 02:00:07 +0000 (Sun, 20 Feb 2022)");
  script_name("Debian LTS: Security Advisory for twisted (DLA-2927-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/02/msg00021.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2927-1");
  script_xref(name:"Advisory-ID", value:"DLA-2927-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/953950");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'twisted'
  package(s) announced via the DLA-2927-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Twisted, a Python event-based framework for
internet applications, is affected by HTTP request splitting
vulnerabilities, and may expose sensitive data when following
redirects. An attacker may bypass validation checks and retrieve
credentials.

CVE-2020-10108

HTTP request splitting vulnerability. When presented with two
content-length headers, it ignored the first header. When the
second content-length value was set to zero, the request body was
interpreted as a pipelined request.

CVE-2020-10109

HTTP request splitting vulnerability. When presented with a
content-length and a chunked encoding header, the content-length
took precedence and the remainder of the request body was
interpreted as a pipelined request.

CVE-2022-21712

Twisted exposes cookies and authorization headers when following
cross-origin redirects. This issue is present in the
`twisted.web.RedirectAgent` and
`twisted.web.BrowserLikeRedirectAgent` functions.");

  script_tag(name:"affected", value:"'twisted' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
16.6.0-2+deb9u1.

We recommend that you upgrade your twisted packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-twisted", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-twisted-bin", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-twisted-bin-dbg", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-twisted-conch", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-twisted-core", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-twisted-mail", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-twisted-names", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-twisted-news", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-twisted-runner", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-twisted-runner-dbg", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-twisted-web", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-twisted-words", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-twisted", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-twisted-bin", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-twisted-bin-dbg", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"twisted-doc", ver:"16.6.0-2+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
