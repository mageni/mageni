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
  script_oid("1.3.6.1.4.1.25623.1.0.892302");
  script_version("2020-08-01T03:00:16+0000");
  script_cve_id("CVE-2018-1152", "CVE-2018-14498", "CVE-2020-13790", "CVE-2020-14152");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-08-03 11:16:30 +0000 (Mon, 03 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-01 03:00:16 +0000 (Sat, 01 Aug 2020)");
  script_name("Debian LTS: Security Advisory for libjpeg-turbo (DLA-2302-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00033.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2302-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/902950");
  script_xref(name:"URL", value:"https://bugs.debian.org/924678");
  script_xref(name:"URL", value:"https://bugs.debian.org/962829");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libjpeg-turbo'
  package(s) announced via the DLA-2302-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were fixed in libjpeg-turbo,
a widely used library for handling JPEG files.

CVE-2018-1152

Denial of service vulnerability caused by a divide by zero when
processing a crafted BMP image in TJBench.

CVE-2018-14498

Denial of service (heap-based buffer over-read and application
crash) via a crafted 8-bit BMP in which one or more of the color
indices is out of range for the number of palette entries.

CVE-2020-13790

Heap-based buffer over-read via a malformed PPM input file.

CVE-2020-14152

jpeg_mem_available() did not honor the max_memory_to_use setting,
possibly causing excessive memory consumption.");

  script_tag(name:"affected", value:"'libjpeg-turbo' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1:1.5.1-2+deb9u1.

We recommend that you upgrade your libjpeg-turbo packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libjpeg-dev", ver:"1:1.5.1-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjpeg-turbo-progs", ver:"1:1.5.1-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjpeg62-turbo", ver:"1:1.5.1-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjpeg62-turbo-dev", ver:"1:1.5.1-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libturbojpeg0", ver:"1:1.5.1-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libturbojpeg0-dev", ver:"1:1.5.1-2+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
