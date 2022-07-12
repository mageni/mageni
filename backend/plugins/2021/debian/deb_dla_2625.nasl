# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892625");
  script_version("2021-04-15T03:00:06+0000");
  script_cve_id("CVE-2021-28374");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-15 10:40:27 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-15 03:00:06 +0000 (Thu, 15 Apr 2021)");
  script_name("Debian LTS: Security Advisory for courier-authlib (DLA-2625-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2625-1");
  script_xref(name:"Advisory-ID", value:"DLA-2625-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/984810");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'courier-authlib'
  package(s) announced via the DLA-2625-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Debian courier-authlib package before 0.71.1-2 for Courier
Authentication Library creates a /run/courier/authdaemon
directory with weak permissions, allowing an attacker to read
user information. This may include a cleartext password in some
configurations. In general, it includes the user's existence,
uid and gids, home and/or Maildir directory, quota, and some
type of password information (such as a hash).");

  script_tag(name:"affected", value:"'courier-authlib' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
0.66.4-9+deb9u1.

We recommend that you upgrade your courier-authlib packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"courier-authdaemon", ver:"0.66.4-9+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"courier-authlib", ver:"0.66.4-9+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"courier-authlib-dev", ver:"0.66.4-9+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"courier-authlib-ldap", ver:"0.66.4-9+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"courier-authlib-mysql", ver:"0.66.4-9+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"courier-authlib-pipe", ver:"0.66.4-9+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"courier-authlib-postgresql", ver:"0.66.4-9+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"courier-authlib-sqlite", ver:"0.66.4-9+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"courier-authlib-userdb", ver:"0.66.4-9+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
