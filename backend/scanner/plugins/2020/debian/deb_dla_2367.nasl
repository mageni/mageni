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
  script_oid("1.3.6.1.4.1.25623.1.0.892367");
  script_version("2020-09-08T09:01:01+0000");
  script_cve_id("CVE-2020-24660");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-09-08 09:56:35 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-08 03:00:07 +0000 (Tue, 08 Sep 2020)");
  script_name("Debian LTS: Security Advisory for lemonldap-ng (DLA-2367-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00006.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2367-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lemonldap-ng'
  package(s) announced via the DLA-2367-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Package : lemonldap-ng
Version : 1.9.7-3+deb9u4
CVE ID : CVE-2020-24660

lemonldap-ng community fixed a vulnerability in the Nginx default
configuration files (CVE-2020-24660).
Debian package does not install any default site, but documentation
provided insecure examples in Nginx configuration before this version.
If you use lemonldap-ng handler with Nginx, you should verify your
configuration files.");

  script_tag(name:"affected", value:"'lemonldap-ng' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
1.9.7-3+deb9u4.

We recommend that you upgrade your lemonldap-ng packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng", ver:"1.9.7-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-doc", ver:"1.9.7-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-fastcgi-server", ver:"1.9.7-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-fr-doc", ver:"1.9.7-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-handler", ver:"1.9.7-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-common-perl", ver:"1.9.7-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-conf-perl", ver:"1.9.7-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-handler-perl", ver:"1.9.7-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-manager-perl", ver:"1.9.7-3+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-portal-perl", ver:"1.9.7-3+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
