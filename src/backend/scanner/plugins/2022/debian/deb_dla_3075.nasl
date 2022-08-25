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
  script_oid("1.3.6.1.4.1.25623.1.0.893075");
  script_version("2022-08-23T10:11:31+0000");
  script_cve_id("CVE-2022-2787");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-23 10:11:31 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-19 01:00:20 +0000 (Fri, 19 Aug 2022)");
  script_name("Debian LTS: Security Advisory for schroot (DLA-3075-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/08/msg00007.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3075-1");
  script_xref(name:"Advisory-ID", value:"DLA-3075-1");
  script_xref(name:"URL", value:"https://codeberg.org/shelter/reschroot/src/tag/release/reschroot-1.6.13/NEWS#L10-L41");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'schroot'
  package(s) announced via the DLA-3075-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Julian Gilbey discovered that schroot, a tool allowing users to execute
commands in a chroot environment, had too permissive rules on chroot or
session names, allowing a denial of service on the schroot service for
all users that may start a schroot session.

Note that existing chroots and sessions are checked during upgrade, and
an upgrade is aborted if any future invalid name is detected.

Problematic session and chroots can be checked before upgrading with the
following command:

schroot --list --all <pipe> LC_ALL=C grep -vE '^[a-z]+:[a-zA-Z0-9][a-zA-Z0-9_.-]*$'

See [link moved to references] for instructions on how to resolve such a situation.");

  script_tag(name:"affected", value:"'schroot' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, this problem has been fixed in version
1.6.10-6+deb10u1.

We recommend that you upgrade your schroot packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"schroot", ver:"1.6.10-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"schroot-common", ver:"1.6.10-6+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
