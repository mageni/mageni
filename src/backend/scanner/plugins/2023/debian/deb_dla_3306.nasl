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
  script_oid("1.3.6.1.4.1.25623.1.0.893306");
  script_version("2023-02-02T10:09:00+0000");
  script_cve_id("CVE-2023-23969");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-02-02 10:09:00 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-02 02:00:06 +0000 (Thu, 02 Feb 2023)");
  script_name("Debian LTS: Security Advisory for python-django (DLA-3306-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/02/msg00000.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3306-1");
  script_xref(name:"Advisory-ID", value:"DLA-3306-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1030251");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django'
  package(s) announced via the DLA-3306-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential Denial of Service (DoS)
vulnerability in Django, a popular Python-based web development
framework.

Parsed values of the Accept-Language HTTP headers are cached by
Django order to avoid repetitive parsing. This could have led to a
potential denial-of-service attack via excessive memory usage if the
raw value of Accept-Language headers was very large.

Accept-Language headers are now limited to a maximum length
specifically in order to avoid this issue.");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, this problem has been fixed in version
1:1.11.29-1+deb10u6.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1:1.11.29-1+deb10u6", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-common", ver:"1:1.11.29-1+deb10u6", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1:1.11.29-1+deb10u6", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1:1.11.29-1+deb10u6", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
