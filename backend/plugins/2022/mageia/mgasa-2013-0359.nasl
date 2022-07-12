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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0359");
  script_cve_id("CVE-2013-6385", "CVE-2013-6386", "CVE-2013-6387", "CVE-2013-6388", "CVE-2013-6389");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-01-14 04:28:00 +0000 (Tue, 14 Jan 2014)");

  script_name("Mageia: Security Advisory (MGASA-2013-0359)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0359");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0359.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11729");
  script_xref(name:"URL", value:"https://drupal.org/SA-CORE-2013-003");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2013/11/22/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drupal' package(s) announced via the MGASA-2013-0359 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Drupal's form API has built-in cross-site request forgery (CSRF)
validation, and also allows any module to perform its own validation on
the form. In certain common cases, form validation functions may execute
unsafe operations (CVE-2013-6385).

Drupal core directly used the mt_rand() pseudorandom number generator for
generating security related strings used in several core modules. It was
found that brute force tools could determine the seeds making these
strings predictable under certain circumstances (CVE-2013-6386).

Image field descriptions are not properly sanitized before they are
printed to HTML, thereby exposing a cross-site scripting vulnerability
(CVE-2013-6387).

A cross-site scripting vulnerability was found in the Color module. A
malicious attacker could trick an authenticated administrative user into
visiting a page containing specific JavaScript that could lead to a
reflected cross-site scripting attack via JavaScript execution in CSS
(CVE-2013-6388).

The Overlay module displays administrative pages as a layer over the
current page (using JavaScript), rather than replacing the page in the
browser window. The Overlay module did not sufficiently validate URLs
prior to displaying their contents, leading to an open redirect
vulnerability (CVE-2013-6389).");

  script_tag(name:"affected", value:"'drupal' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"drupal", rpm:"drupal~7.24~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-mysql", rpm:"drupal-mysql~7.24~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-postgresql", rpm:"drupal-postgresql~7.24~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-sqlite", rpm:"drupal-sqlite~7.24~1.1.mga3", rls:"MAGEIA3"))) {
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
