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
  script_oid("1.3.6.1.4.1.25623.1.0.892208");
  script_version("2020-05-12T03:00:20+0000");
  script_cve_id("CVE-2020-11026", "CVE-2020-11027", "CVE-2020-11028", "CVE-2020-11029");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-05-12 09:56:07 +0000 (Tue, 12 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-12 03:00:20 +0000 (Tue, 12 May 2020)");
  script_name("Debian LTS: Security Advisory for wordpress (DLA-2208-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/05/msg00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2208-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/959391");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wordpress'
  package(s) announced via the DLA-2208-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple CVE(s) were discovered in the src:wordpress package.

CVE-2020-11026

Files with a specially crafted name when uploaded to the
Media section can lead to script execution upon accessing
the file. This requires an authenticated user with privileges
to upload files.

CVE-2020-11027

A password reset link emailed to a user does not expire upon
changing the user password. Access would be needed to the email
account of the user by a malicious party for successful execution.

CVE-2020-11028

Some private posts, which were previously public, can result in
unauthenticated disclosure under a specific set of conditions.

CVE-2020-11029

A vulnerability in the stats() method of class-wp-object-cache.php
can be exploited to execute cross-site scripting (XSS) attacks.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4.1.30+dfsg-0+deb8u1.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"4.1.30+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"4.1.30+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfifteen", ver:"4.1.30+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfourteen", ver:"4.1.30+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentythirteen", ver:"4.1.30+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
