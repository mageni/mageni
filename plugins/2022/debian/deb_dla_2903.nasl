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
  script_oid("1.3.6.1.4.1.25623.1.0.892903");
  script_version("2022-01-30T02:00:27+0000");
  script_cve_id("CVE-2017-13735", "CVE-2017-14265", "CVE-2017-14348", "CVE-2017-14608", "CVE-2017-16909", "CVE-2017-16910", "CVE-2018-20363", "CVE-2018-20364", "CVE-2018-20365", "CVE-2018-5800", "CVE-2018-5801", "CVE-2018-5802", "CVE-2018-5804", "CVE-2018-5805", "CVE-2018-5806", "CVE-2018-5807", "CVE-2018-5808", "CVE-2018-5810", "CVE-2018-5811", "CVE-2018-5812", "CVE-2018-5813", "CVE-2018-5815", "CVE-2018-5817", "CVE-2018-5818", "CVE-2018-5819");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-01-31 10:37:41 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-30 02:00:27 +0000 (Sun, 30 Jan 2022)");
  script_name("Debian LTS: Security Advisory for libraw (DLA-2903-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/01/msg00031.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2903-1");
  script_xref(name:"Advisory-ID", value:"DLA-2903-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libraw'
  package(s) announced via the DLA-2903-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in libraw that
may lead to the execution of arbitrary code, denial of service, or
information leaks.

CVE-2017-13735

There is a floating point exception in the kodak_radc_load_raw
function. It will lead to a remote denial of service attack.

CVE-2017-14265

A Stack-based Buffer Overflow was discovered in xtrans_interpolate
method. It could allow a remote denial of service or code
execution attack.

CVE-2017-14348

There is a heap-based Buffer Overflow in the
processCanonCameraInfo function.

CVE-2017-14608

An out of bounds read flaw related to kodak_65000_load_raw has
been reported in libraw. An attacker could possibly exploit this
flaw to disclose potentially sensitive memory or cause an
application crash.

CVE-2017-16909

An error related to the 'LibRaw::panasonic_load_raw()' function
can be exploited to cause a heap-based buffer overflow and
subsequently cause a crash via a specially crafted TIFF image.
xtrans_interpolate method. It could allow a remote denial of
service or code execution attack.

CVE-2017-16910

An error within the 'LibRaw::xtrans_interpolate()' function can be
exploited to cause an invalid read memory access and subsequently
a Denial of Service condition.

CVE-2018-5800

An off-by-one error within the 'LibRaw::kodak_ycbcr_load_raw()'
function can be exploited to cause a heap-based buffer overflow
and subsequently cause a crash.

CVE-2018-5801

An error within the 'LibRaw::unpack()' function can be exploited
to trigger a NULL pointer dereference.

CVE-2018-5802

An error within the 'kodak_radc_load_raw()' function can be
exploited to cause an out-of-bounds read memory access and
subsequently cause a crash.

CVE-2018-5804

A type confusion error within the 'identify()' function can be
exploited to trigger a division by zero.

CVE-2018-5805

A boundary error within the 'quicktake_100_load_raw()' function
can be exploited to cause a stack-based buffer overflow and
subsequently cause a crash.

CVE-2018-5806

An error within the 'leaf_hdr_load_raw()' function
can be exploited to trigger a NULL pointer dereference.

CVE-2018-5807

An error within the 'samsung_load_raw()' function
can be exploited to cause an out-of-bounds read memory access and
subsequently cause a crash.

CVE-2018-5808

An error within the 'find_green()' function can be exploited to
cause a stack-based buffer overflow and subsequently execute
arbitrary code.

CVE-2018-5810

An error within the 'rollei_load_raw()' function can be exploited
to cause a heap-based buffer overflow and subsequently cause a
crash.

CVE-2018-5811

An error within the 'nikon_coolsc ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'libraw' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
0.17.2-6+deb9u2.

We recommend that you upgrade your libraw packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libraw-bin", ver:"0.17.2-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libraw-dev", ver:"0.17.2-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libraw-doc", ver:"0.17.2-6+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libraw15", ver:"0.17.2-6+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
