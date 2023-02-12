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
  script_oid("1.3.6.1.4.1.25623.1.0.893278");
  script_version("2023-01-24T10:12:05+0000");
  script_cve_id("CVE-2022-1354", "CVE-2022-1355", "CVE-2022-2056", "CVE-2022-2057", "CVE-2022-2058", "CVE-2022-2867", "CVE-2022-2868", "CVE-2022-2869", "CVE-2022-34526", "CVE-2022-3570", "CVE-2022-3597", "CVE-2022-3598", "CVE-2022-3599", "CVE-2022-3626", "CVE-2022-3627", "CVE-2022-3970");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-01-24 10:12:05 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-08 12:48:00 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"creation_date", value:"2023-01-21 02:00:16 +0000 (Sat, 21 Jan 2023)");
  script_name("Debian LTS: Security Advisory for tiff (DLA-3278-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00018.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3278-1");
  script_xref(name:"Advisory-ID", value:"DLA-3278-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1011160");
  script_xref(name:"URL", value:"https://bugs.debian.org/1014494");
  script_xref(name:"URL", value:"https://bugs.debian.org/1022555");
  script_xref(name:"URL", value:"https://bugs.debian.org/1024737");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff'
  package(s) announced via the DLA-3278-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in tiff, a library and tools
providing support for the Tag Image File Format (TIFF), leading to
denial of service (DoS) and possibly local code execution.

CVE-2022-1354

A heap buffer overflow flaw was found in Libtiffs' tiffinfo.c in
TIFFReadRawDataStriped() function. This flaw allows an attacker to
pass a crafted TIFF file to the tiffinfo tool, triggering a heap
buffer overflow issue and causing a crash that leads to a denial
of service.

CVE-2022-1355

A stack buffer overflow flaw was found in Libtiffs' tiffcp.c in
main() function. This flaw allows an attacker to pass a crafted
TIFF file to the tiffcp tool, triggering a stack buffer overflow
issue, possibly corrupting the memory, and causing a crash that
leads to a denial of service.

CVE-2022-2056, CVE-2022-2057, CVE-2022-2058

Divide By Zero error in tiffcrop allows attackers to cause a
denial-of-service via a crafted tiff file.

CVE-2022-2867, CVE-2022-2868, CVE-2022-2869

libtiff's tiffcrop utility has underflow and input validation flaw
that can lead to out of bounds read and write. An attacker who
supplies a crafted file to tiffcrop (likely via tricking a user to
run tiffcrop on it with certain parameters) could cause a crash or
in some cases, further exploitation.

CVE-2022-3570, CVE-2022-3598

Multiple heap buffer overflows in tiffcrop.c utility in libtiff
allows attacker to trigger unsafe or out of bounds memory access
via crafted TIFF image file which could result into application
crash, potential information disclosure or any other
context-dependent impact.

CVE-2022-3597, CVE-2022-3626, CVE-2022-3627

Out-of-bounds write, allowing attackers to cause a
denial-of-service via a crafted tiff file.

CVE-2022-3599

Out-of-bounds read in writeSingleSection in tools/tiffcrop.c,
allowing attackers to cause a denial-of-service via a crafted tiff
file.

CVE-2022-3970

Affects the function TIFFReadRGBATileExt of the file
libtiff/tif_getimage.c. The manipulation leads to integer
overflow.

CVE-2022-34526

A stack overflow was discovered in the _TIFFVGetField function of
Tiffsplit. This vulnerability allows attackers to cause a Denial
of Service (DoS) via a crafted TIFF file parsed by the 'tiffsplit'
or 'tiffcrop' utilities.");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
4.1.0+git191117-2~deb10u5.

We recommend that you upgrade your tiff packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libtiff-dev", ver:"4.1.0+git191117-2~deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.1.0+git191117-2~deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.1.0+git191117-2~deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.1.0+git191117-2~deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.1.0+git191117-2~deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiff5-dev", ver:"4.1.0+git191117-2~deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.1.0+git191117-2~deb10u5", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
