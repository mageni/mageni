# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893289");
  script_version("2023-01-31T10:08:41+0000");
  script_cve_id("CVE-2020-4051", "CVE-2021-23450");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-27 18:13:00 +0000 (Mon, 27 Dec 2021)");
  script_tag(name:"creation_date", value:"2023-01-30 09:59:02 +0000 (Mon, 30 Jan 2023)");
  script_name("Debian LTS: Security Advisory for dojo (DLA-3289-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00030.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3289-1");
  script_xref(name:"Advisory-ID", value:"DLA-3289-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/970000");
  script_xref(name:"URL", value:"https://bugs.debian.org/1014785");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dojo'
  package(s) announced via the DLA-3289-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were found in dojo, a modular JavaScript toolkit,
that could result in information disclosure.

CVE-2020-4051

The Dijit Editor's LinkDialog plugin of dojo 1.14.0 to 1.14.7 is
vulnerable to cross-site scripting (XSS) attacks.

CVE-2021-23450

Prototype pollution vulnerability via the setObject() function.");

  script_tag(name:"affected", value:"'dojo' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1.14.2+dfsg1-1+deb10u3.

We recommend that you upgrade your dojo packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libjs-dojo-core", ver:"1.14.2+dfsg1-1+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjs-dojo-dijit", ver:"1.14.2+dfsg1-1+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjs-dojo-dojox", ver:"1.14.2+dfsg1-1+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"shrinksafe", ver:"1.14.2+dfsg1-1+deb10u3", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
