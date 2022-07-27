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
  script_oid("1.3.6.1.4.1.25623.1.0.892470");
  script_version("2020-12-02T04:00:14+0000");
  script_cve_id("CVE-2017-18206", "CVE-2018-0502", "CVE-2018-1071", "CVE-2018-1083", "CVE-2018-1100", "CVE-2018-13259", "CVE-2019-20044");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-12-02 11:21:40 +0000 (Wed, 02 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-02 04:00:14 +0000 (Wed, 02 Dec 2020)");
  script_name("Debian LTS: Security Advisory for zsh (DLA-2470-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00000.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2470-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/908000");
  script_xref(name:"URL", value:"https://bugs.debian.org/894044");
  script_xref(name:"URL", value:"https://bugs.debian.org/894043");
  script_xref(name:"URL", value:"https://bugs.debian.org/895225");
  script_xref(name:"URL", value:"https://bugs.debian.org/951458");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zsh'
  package(s) announced via the DLA-2470-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were found and corrected in zsh, a powerful
shell and scripting language. Off-by-one errors, wrong parsing of shebang lines
and buffer overflows may lead to unexpected behavior. A local, unprivileged
user can create a specially crafted message file or directory path. If the
receiving user is privileged or traverses the aforementioned path, this leads
to privilege escalation.");

  script_tag(name:"affected", value:"'zsh' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
5.3.1-4+deb9u4.

We recommend that you upgrade your zsh packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"zsh", ver:"5.3.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"zsh-common", ver:"5.3.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"zsh-dev", ver:"5.3.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"zsh-doc", ver:"5.3.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"zsh-static", ver:"5.3.1-4+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
