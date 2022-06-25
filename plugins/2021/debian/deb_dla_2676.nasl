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
  script_oid("1.3.6.1.4.1.25623.1.0.892676");
  script_version("2021-06-06T03:00:07+0000");
  script_cve_id("CVE-2021-33203", "CVE-2021-33571");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-06-07 10:15:34 +0000 (Mon, 07 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-06 03:00:07 +0000 (Sun, 06 Jun 2021)");
  script_name("Debian LTS: Security Advisory for python-django (DLA-2676-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/06/msg00004.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2676-1");
  script_xref(name:"Advisory-ID", value:"DLA-2676-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/989394");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django'
  package(s) announced via the DLA-2676-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two issues were discovered in Django, the Python-based web
development framework:

  * CVE-2021-33203: Potential directory traversal via admindocs

Staff members could use the admindocs TemplateDetailView view to
check the existence of arbitrary files. Additionally, if (and only
if) the default admindocs templates have been customized by the
developers to also expose the file contents, then not only the
existence but also the file contents would have been exposed.

As a mitigation, path sanitation is now applied and only files
within the template root directories can be loaded.

This issue has low severity, according to the Django security
policy.

Thanks to Rasmus Lerchedahl Petersen and Rasmus Wriedt Larsen from
the CodeQL Python team for the report.

  * CVE-2021-33571: Possible indeterminate SSRF, RFI, and LFI attacks
since validators accepted leading zeros in IPv4 addresses

URLValidator, validate_ipv4_address(), and
validate_ipv46_address() didn't prohibit leading zeros in octal
literals. If you used such values you could suffer from
indeterminate SSRF, RFI, and LFI attacks.

validate_ipv4_address() and validate_ipv46_address() validators
were not affected on Python 3.9.5+.

This issue has medium severity, according to the Django security
policy.");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 'Stretch', this problem has been fixed in version
1:1.10.7-2+deb9u14.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1:1.10.7-2+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-common", ver:"1:1.10.7-2+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1:1.10.7-2+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1:1.10.7-2+deb9u14", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
