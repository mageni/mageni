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
  script_oid("1.3.6.1.4.1.25623.1.0.893044");
  script_version("2022-06-09T14:06:34+0000");
  script_cve_id("CVE-2021-27218", "CVE-2021-27219", "CVE-2021-28153");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-06-10 10:05:32 +0000 (Fri, 10 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-07 10:15:00 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2022-06-07 01:00:10 +0000 (Tue, 07 Jun 2022)");
  script_name("Debian LTS: Security Advisory for glib2.0 (DLA-3044-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/06/msg00006.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3044-1");
  script_xref(name:"Advisory-ID", value:"DLA-3044-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/984969");
  script_xref(name:"URL", value:"https://bugs.debian.org/982778");
  script_xref(name:"URL", value:"https://bugs.debian.org/982779");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib2.0'
  package(s) announced via the DLA-3044-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were found in glib2.0, a general-purpose
utility library for the GNOME environment. 

CVE-2021-27218

If g_byte_array_new_take() was called with a buffer of 4GB or more on a
64-bit platform, the length would be truncated modulo 2**32, causing
unintended length truncation.

CVE-2021-27219

The function g_bytes_new has an integer overflow on 64-bit platforms due to
an implicit cast from 64 bits to 32 bits. The overflow could potentially
lead to memory corruption.

CVE-2021-28153

When g_file_replace() is used with G_FILE_CREATE_REPLACE_DESTINATION to
replace a path that is a dangling symlink, it incorrectly also creates the
target of the symlink as an empty file, which could conceivably have
security relevance if the symlink is attacker-controlled. (If the path is
a symlink to a file that already exists, then the contents of that file
correctly remain unchanged.)");

  script_tag(name:"affected", value:"'glib2.0' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.50.3-2+deb9u3.

We recommend that you upgrade your glib2.0 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.50.3-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0-dbg", ver:"2.50.3-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-bin", ver:"2.50.3-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-data", ver:"2.50.3-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-dev", ver:"2.50.3-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-doc", ver:"2.50.3-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-tests", ver:"2.50.3-2+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-udeb", ver:"2.50.3-2+deb9u3", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
