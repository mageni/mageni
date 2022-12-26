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
  script_oid("1.3.6.1.4.1.25623.1.0.893239");
  script_version("2022-12-15T10:11:09+0000");
  script_cve_id("CVE-2022-24765", "CVE-2022-29187", "CVE-2022-39253", "CVE-2022-39260");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-12-15 10:11:09 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-23 02:10:00 +0000 (Sat, 23 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-12-14 02:00:16 +0000 (Wed, 14 Dec 2022)");
  script_name("Debian LTS: Security Advisory for git (DLA-3239-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/12/msg00025.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3239-1");
  script_xref(name:"Advisory-ID", value:"DLA-3239-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1014848");
  script_xref(name:"URL", value:"https://bugs.debian.org/1022046");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git'
  package(s) announced via the DLA-3239-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues were found in Git, a distributed revision control
system. An attacker may cause other local users into executing
arbitrary commands, leak information from the local filesystem, and
bypass restricted shell.

Note: Due to new security checks, access to repositories owned and
accessed by different local users may now be rejected by Git. In case
changing ownership is not practical, git displays a way to bypass
these checks using the new 'safe.directory' configuration entry.

CVE-2022-24765

Git is not checking the ownership of directories in a local
multi-user system when running commands specified in the local
repository configuration. This allows the owner of the repository
to cause arbitrary commands to be executed by other users who
access the repository.

CVE-2022-29187

An unsuspecting user could still be affected by the issue reported
in CVE-2022-24765, for example when navigating as root into a
shared tmp directory that is owned by them, but where an attacker
could create a git repository.

CVE-2022-39253

Exposure of sensitive information to a malicious actor. When
performing a local clone (where the source and target of the clone
are on the same volume), Git copies the contents of the source's
`$GIT_DIR/objects` directory into the destination by either
creating hardlinks to the source contents, or copying them (if
hardlinks are disabled via `--no-hardlinks`). A malicious actor
could convince a victim to clone a repository with a symbolic link
pointing at sensitive information on the victim's machine.

CVE-2022-39260

`git shell` improperly uses an `int` to represent the number of
entries in the array, allowing a malicious actor to intentionally
overflow the return value, leading to arbitrary heap
writes. Because the resulting array is then passed to `execv()`,
it is possible to leverage this attack to gain remote code
execution on a victim machine.");

  script_tag(name:"affected", value:"'git' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1:2.20.1-2+deb10u5.

We recommend that you upgrade your git packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"git", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-all", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-cvs", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-daemon-run", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-daemon-sysvinit", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-doc", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-el", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-email", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-gui", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-man", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-mediawiki", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-svn", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gitk", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gitweb", ver:"1:2.20.1-2+deb10u5", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
