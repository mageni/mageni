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
  script_oid("1.3.6.1.4.1.25623.1.0.704467");
  script_version("2019-06-21T08:28:14+0000");
  script_cve_id("CVE-2019-12735");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-06-21 08:28:14 +0000 (Fri, 21 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-20 02:00:05 +0000 (Thu, 20 Jun 2019)");
  script_name("Debian Security Advisory DSA 4467-1 (vim - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4467.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4467-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim'
  package(s) announced via the DSA-4467-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"User Arminius discovered a vulnerability in Vim, an enhanced version of the
  standard UNIX editor Vi (Vi IMproved). The Common vulnerabilities and exposures project identifies the following problem:

  Editors typically provide a way to embed editor configuration commands (aka
  modelines) which are executed once a file is opened, while harmful commands
  are filtered by a sandbox mechanism. It was discovered that the source
  command (used to include and execute another file) was not filtered, allowing
  shell command execution with a carefully crafted file opened in Vim.");

  script_tag(name:"affected", value:"'vim' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
  version 2:8.0.0197-4+deb9u2.

  We recommend that you upgrade your vim packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.0.0197-4+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:8.0.0197-4+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-common", ver:"2:8.0.0197-4+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-doc", ver:"2:8.0.0197-4+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gnome", ver:"2:8.0.0197-4+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:8.0.0197-4+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:8.0.0197-4+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gui-common", ver:"2:8.0.0197-4+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:8.0.0197-4+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-runtime", ver:"2:8.0.0197-4+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:8.0.0197-4+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:8.0.0197-4+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
