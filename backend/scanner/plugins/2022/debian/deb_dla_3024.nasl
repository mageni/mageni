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
  script_oid("1.3.6.1.4.1.25623.1.0.893024");
  script_version("2022-05-31T03:05:10+0000");
  script_cve_id("CVE-2020-9402");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-31 03:05:10 +0000 (Tue, 31 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"creation_date", value:"2022-05-27 01:00:06 +0000 (Fri, 27 May 2022)");
  script_name("Debian LTS: Security Advisory for python-django (DLA-3024-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/05/msg00035.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3024-1");
  script_xref(name:"Advisory-ID", value:"DLA-3024-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/953102");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django'
  package(s) announced via the DLA-3024-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential SQL injection
vulnerability in the Django web development framework.

Untrusted data was used as a tolerance parameter in GIS functions and
aggregates when using the Oracle database backend. By passing a
suitably crafted tolerance to GIS functions and aggregates on Oracle,
it was potentially possible to break escaping and inject malicious
SQL.");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 'Stretch', this problem has been fixed in version
1:1.10.7-2+deb9u17.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1:1.10.7-2+deb9u17", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-common", ver:"1:1.10.7-2+deb9u17", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1:1.10.7-2+deb9u17", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1:1.10.7-2+deb9u17", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
