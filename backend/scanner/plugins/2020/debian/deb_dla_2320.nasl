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
  script_oid("1.3.6.1.4.1.25623.1.0.892320");
  script_version("2020-08-17T13:22:03+0000");
  script_cve_id("CVE-2017-18367");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-08-18 10:12:19 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-17 13:22:03 +0000 (Mon, 17 Aug 2020)");
  script_name("Debian LTS: Security Advisory for golang-github-seccomp-libseccomp-golang (DLA-2320-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00016.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2320-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/927981");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-seccomp-libseccomp-golang'
  package(s) announced via the DLA-2320-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A process running under a restrictive seccomp filter that specified
multiple syscall arguments could bypass intended access restrictions by
specifying a single matching argument.

Additionally, runc has been rebuilt with the fixed package.");

  script_tag(name:"affected", value:"'golang-github-seccomp-libseccomp-golang' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
0.0~git20150813.0.1b506fc-2+deb9u1.

We recommend that you upgrade your golang-github-seccomp-libseccomp-golang
and runc packages, and recompile own Go code using
golang-github-seccomp-libseccomp-golang.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"golang-github-seccomp-libseccomp-golang-dev", ver:"0.0~git20150813.0.1b506fc-2+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
