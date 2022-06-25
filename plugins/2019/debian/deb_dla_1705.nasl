# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891705");
  script_version("2019-05-24T11:20:30+0000");
  script_cve_id("CVE-2017-11332", "CVE-2017-11358", "CVE-2017-11359", "CVE-2017-15371");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1705-1] sox security update)");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2019-03-06 00:00:00 +0100 (Wed, 06 Mar 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00007.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"sox on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
14.4.1-5+deb8u3.

We recommend that you upgrade your sox packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in SoX (Sound eXchange),
a sound processing program:

CVE-2017-11332

The startread function (wav.c) is affected by a divide-by-zero
vulnerability when processing WAV file with zero channel count. This
flaw might be leveraged by remote attackers using a crafted WAV file
to perform denial of service (application crash).

CVE-2017-11358

The read_samples function (hcom.c) is affected by an invalid memory read
vulnerability when processing HCOM files with invalid dictionaries. This
flaw might be leveraged by remote attackers using a crafted HCOM file to
perform denial of service (application crash).

CVE-2017-11359

The wavwritehdr function (wav.c) is affected by a divide-by-zero
vulnerability when processing WAV files with invalid channel count over
16 bits. This flaw might be leveraged by remote attackers using a crafted
WAV file to perform denial of service (application crash).

CVE-2017-15371

The sox_append_comment() function (formats.c) is vulnerable to a reachable
assertion when processing FLAC files with metadata declaring more comments
than provided. This flaw might be leveraged by remote attackers using
crafted FLAC data to perform denial of service (application crash).");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libsox-dev", ver:"14.4.1-5+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsox-fmt-all", ver:"14.4.1-5+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsox-fmt-alsa", ver:"14.4.1-5+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsox-fmt-ao", ver:"14.4.1-5+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsox-fmt-base", ver:"14.4.1-5+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsox-fmt-mp3", ver:"14.4.1-5+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsox-fmt-oss", ver:"14.4.1-5+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsox-fmt-pulse", ver:"14.4.1-5+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsox2", ver:"14.4.1-5+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sox", ver:"14.4.1-5+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}