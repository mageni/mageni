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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0356");
  script_cve_id("CVE-2021-28658", "CVE-2021-31542", "CVE-2021-32052", "CVE-2021-33203", "CVE-2021-33571", "CVE-2021-35042");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-08 18:01:00 +0000 (Thu, 08 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0356)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0356");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0356.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28802");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2021/apr/06/security-releases/");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2021/may/04/security-releases/");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2021/may/06/security-releases/");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2021/jun/02/security-releases/");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2021/jul/01/security-releases/");
  script_xref(name:"URL", value:"https://docs.djangoproject.com/en/dev/releases/3.1.8/");
  script_xref(name:"URL", value:"https://docs.djangoproject.com/en/dev/releases/3.1.9/");
  script_xref(name:"URL", value:"https://docs.djangoproject.com/en/dev/releases/3.1.10/");
  script_xref(name:"URL", value:"https://docs.djangoproject.com/en/dev/releases/3.1.11/");
  script_xref(name:"URL", value:"https://docs.djangoproject.com/en/dev/releases/3.1.12/");
  script_xref(name:"URL", value:"https://docs.djangoproject.com/en/dev/releases/3.1.13/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2622");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4902-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4932-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4975-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the MGASA-2021-0356 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Django 2.2 before 2.2.20, 3.0 before 3.0.14, and 3.1 before 3.1.8,
MultiPartParser allowed directory traversal via uploaded files with suitably
crafted file names. Built-in upload handlers were not affected by this
vulnerability (CVE-2021-28658).

In Django 2.2 before 2.2.21, 3.1 before 3.1.9, and 3.2 before 3.2.1,
MultiPartParser, UploadedFile, and FieldFile allowed directory traversal via
uploaded files with suitably crafted file names (CVE-2021-31542).

In Django 2.2 before 2.2.22, 3.1 before 3.1.10, and 3.2 before 3.2.2 (with
Python 3.9.5+), URLValidator does not prohibit newlines and tabs (unless the
URLField form field is used). If an application uses values with newlines in
an HTTP response, header injection can occur. Django itself is unaffected
because HttpResponse prohibits newlines in HTTP headers (CVE-2021-32052).

Django before 2.2.24, 3.x before 3.1.12, and 3.2.x before 3.2.4 has a potential
directory traversal via django.contrib.admindocs. Staff members could use the
TemplateDetailView view to check the existence of arbitrary files.
Additionally, if (and only if) the default admindocs templates have been
customized by application developers to also show file contents, then not only
the existence but also the file contents would have been exposed. In other
words, there is directory traversal outside of the template root directories
(CVE-2021-33203).

In Django 2.2 before 2.2.24, 3.x before 3.1.12, and 3.2 before 3.2.4,
URLValidator, validate_ipv4_address, and validate_ipv46_address do not prohibit
leading zero characters in octal literals. This may allow a bypass of access
control that is based on IP addresses. (validate_ipv4_address and
validate_ipv46_address are unaffected with Python 3.9.5+..) (CVE-2021-33571).

Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows QuerySet.order_by
SQL injection if order_by is untrusted input from a client of a web application
(CVE-2021-35042).

python-django package is updated to 3.1.13 version to fix these security
issues among other upstream bugfixes, see upstream release notes.");

  script_tag(name:"affected", value:"'python-django' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~3.1.13~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~3.1.13~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
