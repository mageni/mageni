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
  script_oid("1.3.6.1.4.1.25623.1.0.704945");
  script_version("2021-07-30T03:00:16+0000");
  script_cve_id("CVE-2021-21775", "CVE-2021-21779", "CVE-2021-30663", "CVE-2021-30665", "CVE-2021-30689", "CVE-2021-30720", "CVE-2021-30734", "CVE-2021-30744", "CVE-2021-30749", "CVE-2021-30758", "CVE-2021-30795", "CVE-2021-30797", "CVE-2021-30799");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-30 03:00:16 +0000 (Fri, 30 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-30 03:00:16 +0000 (Fri, 30 Jul 2021)");
  script_name("Debian: Security Advisory for webkit2gtk (DSA-4945-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4945.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4945-1");
  script_xref(name:"Advisory-ID", value:"DSA-4945-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk'
  package(s) announced via the DSA-4945-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been discovered in the webkit2gtk
web engine:

CVE-2021-21775
Marcin Towalski discovered that a specially crafted web page can
lead to a potential information leak and further memory
corruption. In order to trigger the vulnerability, a victim must
be tricked into visiting a malicious webpage.

CVE-2021-21779
Marcin Towalski discovered that a specially crafted web page can
lead to a potential information leak and further memory
corruption. In order to trigger the vulnerability, a victim must
be tricked into visiting a malicious webpage.

CVE-2021-30663
An anonymous researcher discovered that processing maliciously
crafted web content may lead to arbitrary code execution.

CVE-2021-30665
yangkang discovered that processing maliciously crafted web
content may lead to arbitrary code execution. Apple is aware of a
report that this issue may have been actively exploited.

CVE-2021-30689
An anonymous researcher discovered that processing maliciously
crafted web content may lead to universal cross site scripting.

CVE-2021-30720
David Schutz discovered that a malicious website may be able to
access restricted ports on arbitrary servers.

CVE-2021-30734
Jack Dates discovered that processing maliciously crafted web
content may lead to arbitrary code execution.

CVE-2021-30744
Dan Hite discovered that processing maliciously crafted web
content may lead to universal cross site scripting.

CVE-2021-30749
An anonymous researcher discovered that processing maliciously
crafted web content may lead to arbitrary code execution.

CVE-2021-30758
Christoph Guttandin discovered that processing maliciously crafted
web content may lead to arbitrary code execution.

CVE-2021-30795
Sergei Glazunov discovered that processing maliciously crafted web
content may lead to arbitrary code execution.

CVE-2021-30797
Ivan Fratric discovered that processing maliciously crafted web
content may lead to code execution.

CVE-2021-30799
Sergei Glazunov discovered that processing maliciously crafted web
content may lead to arbitrary code execution.");

  script_tag(name:"affected", value:"'webkit2gtk' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 2.32.3-1~deb10u1.

We recommend that you upgrade your webkit2gtk packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-javascriptcoregtk-4.0", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-webkit2-4.0", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-18", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-bin", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-dev", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37-gtk2", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-dev", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-doc", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"webkit2gtk-driver", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
