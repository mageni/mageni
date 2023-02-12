# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893277");
  script_version("2023-01-23T10:11:56+0000");
  script_cve_id("CVE-2022-42906");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-21 02:00:03 +0000 (Sat, 21 Jan 2023)");
  script_name("Debian LTS: Security Advisory for powerline-gitstatus (DLA-3277-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00017.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3277-1");
  script_xref(name:"Advisory-ID", value:"DLA-3277-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'powerline-gitstatus'
  package(s) announced via the DLA-3277-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Powerline Gitstatus, a status line plugin for the VIM editor, allows
arbitrary code execution. Git repositories can contain per-repository
configuration that changes the behavior of git, including running arbitrary
commands. When using powerline-gitstatus, changing to a directory
automatically runs git commands in order to display information about the
current repository in the prompt. If an attacker can convince a user to
change their current directory to one controlled by the attacker, such as
in a shared filesystem or extracted archive, powerline-gitstatus will run
arbitrary commands under the attacker's control.");

  script_tag(name:"affected", value:"'powerline-gitstatus' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, this problem has been fixed in version
1.3.2-0+deb10u1.

We recommend that you upgrade your powerline-gitstatus packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"powerline-gitstatus", ver:"1.3.2-0+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-powerline-gitstatus", ver:"1.3.2-0+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
