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
  script_oid("1.3.6.1.4.1.25623.1.0.893177");
  script_version("2022-11-24T10:18:54+0000");
  script_cve_id("CVE-2021-45115", "CVE-2021-45116", "CVE-2022-28346");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-11-24 10:18:54 +0000 (Thu, 24 Nov 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-19 15:48:00 +0000 (Tue, 19 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-11-24 02:00:10 +0000 (Thu, 24 Nov 2022)");
  script_name("Debian LTS: Security Advisory for python-django (DLA-3177-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/11/msg00005.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3177-1");
  script_xref(name:"Advisory-ID", value:"DLA-3177-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1003113");
  script_xref(name:"URL", value:"https://bugs.debian.org/1009677");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django'
  package(s) announced via the DLA-3177-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were multiple vulnerabilities in Django, a
popular Python-based development framework:

* CVE-2022-28346: An issue was discovered in Django 2.2 before
2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4.
QuerySet.annotate(), aggregate(), and extra() methods are subject
to SQL injection in column aliases via a crafted dictionary (with
dictionary expansion) as the passed **kwargs.

* CVE-2021-45115: An issue was discovered in Django 2.2 before
2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1.
UserAttributeSimilarityValidator incurred significant overhead in
evaluating a submitted password that was artificially large in
relation to the comparison values. In a situation where access to
user registration was unrestricted, this provided a potential
vector for a denial-of-service attack.

* CVE-2021-45116: An issue was discovered in Django 2.2 before
2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1. Due to leveraging
the Django Template Language's variable resolution logic, the
dictsort template filter was potentially vulnerable to information
disclosure, or an unintended method call, if passed a suitably
crafted key.");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1:1.11.29-1+deb10u3.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1:1.11.29-1+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-common", ver:"1:1.11.29-1+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1:1.11.29-1+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1:1.11.29-1+deb10u3", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
