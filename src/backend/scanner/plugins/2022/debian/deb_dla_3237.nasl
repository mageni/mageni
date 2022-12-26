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
  script_oid("1.3.6.1.4.1.25623.1.0.893237");
  script_version("2022-12-13T10:10:56+0000");
  script_cve_id("CVE-2021-37701", "CVE-2021-37712");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-12-13 10:10:56 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 18:26:00 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"creation_date", value:"2022-12-13 02:00:10 +0000 (Tue, 13 Dec 2022)");
  script_name("Debian LTS: Security Advisory for node-tar (DLA-3237-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/12/msg00023.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3237-1");
  script_xref(name:"Advisory-ID", value:"DLA-3237-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/993981");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'node-tar'
  package(s) announced via the DLA-3237-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cache poisoning vulnerabilities were found in node-tar, a Node.js module
used to read and write portable tar archives, which may result in
arbitrary file creation or overwrite.

CVE-2021-37701

It was discovered that node-tar performed insufficient symlink
protection, thereby making directory cache vulnerable to poisoning
using symbolic links.

Upon extracting an archive containing a directory 'foo/bar' followed
with a symbolic link 'foo\\bar' to an arbitrary location, node-tar
would extract arbitrary files into the symlink target, thus allowing
arbitrary file creation and overwrite.

Moreover, on case-insensitive filesystems, a similar issue occurred
with a directory 'FOO' followed with a symbolic link 'foo'.

CVE-2021-37712

Similar to CVE-2021-37701, a specially crafted tar archive
containing two directories and a symlink with names containing
unicode values that normalized to the same value, would bypass
node-tar's symlink checks on directories, thus allowing arbitrary
file creation and overwrite.");

  script_tag(name:"affected", value:"'node-tar' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
4.4.6+ds1-3+deb10u2.

We recommend that you upgrade your node-tar packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"node-tar", ver:"4.4.6+ds1-3+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
