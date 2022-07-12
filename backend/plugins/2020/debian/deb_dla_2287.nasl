# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892287");
  script_version("2020-07-24T03:00:12+0000");
  script_cve_id("CVE-2017-18267", "CVE-2018-16646", "CVE-2018-20481", "CVE-2018-21009", "CVE-2019-10872", "CVE-2019-12293", "CVE-2019-9200", "CVE-2019-9631");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-24 03:00:12 +0000 (Fri, 24 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-24 03:00:12 +0000 (Fri, 24 Jul 2020)");
  script_name("Debian LTS: Security Advisory for poppler (DLA-2287-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00018.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2287-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/898357");
  script_xref(name:"URL", value:"https://bugs.debian.org/909802");
  script_xref(name:"URL", value:"https://bugs.debian.org/917325");
  script_xref(name:"URL", value:"https://bugs.debian.org/923414");
  script_xref(name:"URL", value:"https://bugs.debian.org/926530");
  script_xref(name:"URL", value:"https://bugs.debian.org/926673");
  script_xref(name:"URL", value:"https://bugs.debian.org/929423");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the DLA-2287-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues were found in Poppler, a PDF rendering library, that could
lead to denial of service or possibly other unspecified impact when
processing maliciously crafted documents.");

  script_tag(name:"affected", value:"'poppler' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
0.48.0-2+deb9u3.

We recommend that you upgrade your poppler packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-poppler-0.18", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-cpp-dev", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-cpp0v5", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-dev", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib-dev", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib-doc", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib8", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-private-dev", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt4-4", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt4-dev", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt5-1", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt5-dev", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpoppler64", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"poppler-dbg", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"0.48.0-2+deb9u3", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
