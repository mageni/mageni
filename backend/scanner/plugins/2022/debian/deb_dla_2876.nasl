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
  script_oid("1.3.6.1.4.1.25623.1.0.892876");
  script_version("2022-01-11T02:00:08+0000");
  script_cve_id("CVE-2017-17087", "CVE-2019-20807", "CVE-2021-3778", "CVE-2021-3796");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-01-11 02:00:08 +0000 (Tue, 11 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-11 02:00:08 +0000 (Tue, 11 Jan 2022)");
  script_name("Debian LTS: Security Advisory for vim (DLA-2876-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/01/msg00003.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2876-1");
  script_xref(name:"Advisory-ID", value:"DLA-2876-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim'
  package(s) announced via the DLA-2876-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues have been discovered in vim: an enhanced vi text editor:

CVE-2017-17087
fileio.c in Vim sets the group ownership of a .swp file to the editor's primary
group (which may be different from the group ownership of the original file),
which allows local users to obtain sensitive information by leveraging an
applicable group membership.

CVE-2019-20807
Users can circumvent the rvim restricted mode and execute arbitrary OS
commands via scripting interfaces (e.g., Python, Ruby, or Lua).

CVE-2021-3778
Heap-based Buffer Overflow with invalid utf-8 character was detected in
regexp_nfa.c.

CVE-2021-3796
Heap Use-After-Free memory error was detected in normal.c. A successful
exploitation may lead to code execution.");

  script_tag(name:"affected", value:"'vim' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2:8.0.0197-4+deb9u4.

We recommend that you upgrade your vim packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-common", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-doc", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gnome", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gui-common", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-runtime", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:8.0.0197-4+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
