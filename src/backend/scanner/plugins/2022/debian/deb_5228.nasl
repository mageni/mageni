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
  script_oid("1.3.6.1.4.1.25623.1.0.705228");
  script_version("2022-09-13T08:42:54+0000");
  script_cve_id("CVE-2021-44648", "CVE-2021-46829");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-13 08:42:54 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-20 15:01:00 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-09-13 01:00:11 +0000 (Tue, 13 Sep 2022)");
  script_name("Debian: Security Advisory for gdk-pixbuf (DSA-5228-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5228.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5228-1");
  script_xref(name:"Advisory-ID", value:"DSA-5228-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdk-pixbuf'
  package(s) announced via the DSA-5228-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in gdk-pixbuf, the GDK
Pixbuf library.

CVE-2021-44648
Sahil Dhar reported a heap-based buffer overflow vulnerability when
decoding the lzw compressed stream of image data, which may result
in the execution of arbitrary code or denial of service if a
malformed GIF image is processed.

CVE-2021-46829
Pedro Ribeiro reported a heap-based buffer overflow vulnerability
when compositing or clearing frames in GIF files, which may result
in the execution of arbitrary code or denial of service if a
malformed GIF image is processed.");

  script_tag(name:"affected", value:"'gdk-pixbuf' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 2.42.2+dfsg-1+deb11u1.

We recommend that you upgrade your gdk-pixbuf packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gdk-pixbuf-tests", ver:"2.42.2+dfsg-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-gdkpixbuf-2.0", ver:"2.42.2+dfsg-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf-2.0-0", ver:"2.42.2+dfsg-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf-2.0-0-udeb", ver:"2.42.2+dfsg-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf-2.0-dev", ver:"2.42.2+dfsg-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-0-udeb", ver:"2.42.2+dfsg-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-bin", ver:"2.42.2+dfsg-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-common", ver:"2.42.2+dfsg-1+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-doc", ver:"2.42.2+dfsg-1+deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
