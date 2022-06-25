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
  script_oid("1.3.6.1.4.1.25623.1.0.704535");
  script_version("2019-09-28T02:00:08+0000");
  script_cve_id("CVE-2019-5094");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-28 02:00:08 +0000 (Sat, 28 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-28 02:00:08 +0000 (Sat, 28 Sep 2019)");
  script_name("Debian Security Advisory DSA 4535-1 (e2fsprogs - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4535.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4535-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'e2fsprogs'
  package(s) announced via the DSA-4535-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lilith of Cisco Talos discovered a buffer overflow flaw in the quota
code used by e2fsck from the ext2/ext3/ext4 file system utilities.
Running e2fsck on a malformed file system can result in the execution of
arbitrary code.");

  script_tag(name:"affected", value:"'e2fsprogs' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), this problem has been fixed
in version 1.43.4-2+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 1.44.5-1+deb10u2.

We recommend that you upgrade your e2fsprogs packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"e2fsck-static", ver:"1.43.4-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"e2fslibs", ver:"1.43.4-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"e2fslibs-dev", ver:"1.43.4-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"e2fsprogs", ver:"1.43.4-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse2fs", ver:"1.43.4-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcomerr2", ver:"1.43.4-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libss2", ver:"1.43.4-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"e2fsck-static", ver:"1.44.5-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"e2fslibs", ver:"1.44.5-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"e2fslibs-dev", ver:"1.44.5-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"e2fsprogs", ver:"1.44.5-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"e2fsprogs-l10n", ver:"1.44.5-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse2fs", ver:"1.44.5-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcom-err2", ver:"1.44.5-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcomerr2", ver:"1.44.5-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libext2fs-dev", ver:"1.44.5-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libext2fs2", ver:"1.44.5-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libss2", ver:"1.44.5-1+deb10u2", rls:"DEB10"))) {
  report += res;
}

# nb: Those are using a different version scheme, take care of this when overwriting this LSC...
if(!isnull(res = isdpkgvuln(pkg:"comerr-dev", ver:"2.1-1.43.4-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ss-dev", ver:"2.0-1.43.4-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"comerr-dev", ver:"2.1-1.44.5-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ss-dev", ver:"2.0-1.44.5-1+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
