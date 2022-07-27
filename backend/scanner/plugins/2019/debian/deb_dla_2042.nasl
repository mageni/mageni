# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.892042");
  script_version("2019-12-19T03:00:08+0000");
  script_cve_id("CVE-2019-19844");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-12-19 03:00:08 +0000 (Thu, 19 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-19 03:00:08 +0000 (Thu, 19 Dec 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 2042-1] python-django security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/12/msg00024.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2042-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/946937");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django'
  package(s) announced via the DSA-2042-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential account hijack
vulnerability in Django, the Python-based web development
framework.

Django's password-reset form used a case-insensitive query to
retrieve accounts matching the email address requesting the password
reset. Because this typically involves explicit or implicit case
transformations, an attacker who knew the email address associated
with a user account could craft an email address which is distinct
from the address associated with that account, but which -- due to
the behavior of Unicode case transformations -- ceases to be distinct
after case transformation, or which will otherwise compare equal
given database case-transformation or collation behavior. In such a
situation, the attacker can receive a valid password-reset token for
the user account.

To resolve this, two changes were made in Django:

  * After retrieving a list of potentially-matching accounts from the
database, Django's password reset functionality now also checks
the email address for equivalence in Python, using the
recommended identifier-comparison process from Unicode Technical
Report 36, section 2.11.2(B)(2).

  * When generating password-reset emails, Django now sends to the
email address retrieved from the database, rather than the email
address submitted in the password-reset request form.

For more information, please see:");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this issue has been fixed in python-django version
1.7.11-1+deb8u8.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.7.11-1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-common", ver:"1.7.11-1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1.7.11-1+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1.7.11-1+deb8u8", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
