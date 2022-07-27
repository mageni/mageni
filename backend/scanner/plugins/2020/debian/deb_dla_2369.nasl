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
  script_oid("1.3.6.1.4.1.25623.1.0.892369");
  script_version("2020-09-10T09:59:08+0000");
  script_cve_id("CVE-2017-18258", "CVE-2017-8872", "CVE-2018-14404", "CVE-2018-14567", "CVE-2019-19956", "CVE-2019-20388", "CVE-2020-24977", "CVE-2020-7595");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-09-10 10:23:20 +0000 (Thu, 10 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-10 07:28:40 +0000 (Thu, 10 Sep 2020)");
  script_name("Debian LTS: Security Advisory for libxml2 (DLA-2369-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00009.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2369-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/895245");
  script_xref(name:"URL", value:"https://bugs.debian.org/862450");
  script_xref(name:"URL", value:"https://bugs.debian.org/949583");
  script_xref(name:"URL", value:"https://bugs.debian.org/969529");
  script_xref(name:"URL", value:"https://bugs.debian.org/949582");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the DLA-2369-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were corrected in libxml2, the GNOME
XML library.

CVE-2017-8872

Global buffer-overflow in the htmlParseTryOrFinish function.

CVE-2017-18258

The xz_head function in libxml2 allows remote attackers to cause a
denial of service (memory consumption) via a crafted LZMA file,
because the decoder functionality does not restrict memory usage to
what is required for a legitimate file.

CVE-2018-14404

A NULL pointer dereference vulnerability exists in the
xpath.c:xmlXPathCompOpEval() function of libxml2 when parsing an
invalid XPath expression in the XPATH_OP_AND or XPATH_OP_OR case.
Applications processing untrusted XSL format inputs may be
vulnerable to a denial of service attack.

CVE-2018-14567

If the option --with-lzma is used, allows remote attackers to cause
a denial of service (infinite loop) via a crafted XML file.

CVE-2019-19956

The xmlParseBalancedChunkMemoryRecover function has a memory leak
related to newDoc->oldNs.

CVE-2019-20388

A memory leak was found in the xmlSchemaValidateStream function of
libxml2. Applications that use this library may be vulnerable to
memory not being freed leading to a denial of service.

CVE-2020-7595

Infinite loop in xmlStringLenDecodeEntities can cause a denial of
service.

CVE-2020-24977

Out-of-bounds read restricted to xmllint --htmlout.");

  script_tag(name:"affected", value:"'libxml2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.9.4+dfsg1-2.2+deb9u3.

We recommend that you upgrade your libxml2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libxml2", ver:"2.9.4+dfsg1-2.2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxml2-dbg", ver:"2.9.4+dfsg1-2.2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxml2-dev", ver:"2.9.4+dfsg1-2.2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxml2-doc", ver:"2.9.4+dfsg1-2.2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.9.4+dfsg1-2.2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxml2-utils-dbg", ver:"2.9.4+dfsg1-2.2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-libxml2", ver:"2.9.4+dfsg1-2.2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-libxml2-dbg", ver:"2.9.4+dfsg1-2.2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-libxml2", ver:"2.9.4+dfsg1-2.2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-libxml2-dbg", ver:"2.9.4+dfsg1-2.2+deb9u3", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
