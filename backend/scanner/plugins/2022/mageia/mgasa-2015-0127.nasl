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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0127");
  script_cve_id("CVE-2015-2241", "CVE-2015-2316", "CVE-2015-2317");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2015-0127)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0127");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0127.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15528");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2015/mar/09/security-releases/");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2015/mar/18/security-releases/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django, python-django14' package(s) announced via the MGASA-2015-0127 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-django and python-django14 packages fix security
vulnerabilities:

The ModelAdmin.readonly_fields attribute in the Django admin allows
displaying model fields and model attributes. While the former were correctly
escaped, the latter were not. Thus untrusted content could be injected into
the admin, presenting an exploitation vector for XSS attacks (CVE-2015-2241).

Django relies on user input in some cases to redirect the user to an 'on
success' URL. The security checks for these redirects accepted URLs with
leading control characters and so considered URLs like \x08javascript:...
safe. This issue doesn't affect Django currently, however, if a developer
relies on is_safe_url() to provide safe redirect targets and puts such a URL
into a link, they could suffer from an XSS attack as some browsers such as
Google Chrome ignore control characters at the start of a URL in an anchor
href (CVE-2015-2317).

Note that the CVE-2015-2241 issue does not affect python-django14 directly,
but client code using it may be affected. Please see the March 9th upstream
advisory for more information on this.");

  script_tag(name:"affected", value:"'python-django, python-django14' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.5.9~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django-doc", rpm:"python-django-doc~1.5.9~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django14", rpm:"python-django14~1.4.20~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~1.5.9~1.2.mga4", rls:"MAGEIA4"))) {
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
