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
  script_oid("1.3.6.1.4.1.25623.1.0.891872");
  script_version("2019-08-07T02:00:06+0000");
  script_cve_id("CVE-2019-14232", "CVE-2019-14233");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-08-07 02:00:06 +0000 (Wed, 07 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-07 02:00:06 +0000 (Wed, 07 Aug 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1872-1] python-django security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00005.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1872-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/934026");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2019/aug/01/security-releases/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django'
  package(s) announced via the DSA-1872-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were two vulnerabilities in the
Django web development framework:

  * CVE-2019-14232: Prevent a possible denial-of-service in
django.utils.text.Truncator.

If django.utils.text.Truncator's chars() and words() methods were
passed the html=True argument, they were extremely slow to
evaluate certain inputs due to a catastrophic backtracking
vulnerability in a regular expression. The chars() and words()
methods are used to implement the truncatechars_html and
truncatewords_html template filters, which were thus vulnerable.

The regular expressions used by Truncator have been simplified in
order to avoid potential backtracking issues. As a consequence,
trailing punctuation may now at times be included in the
truncated output.

  * CVE-2019-14233: Prevent a possible denial-of-service in strip_tags().

Due to the behavior of the underlying HTMLParser,
django.utils.html.strip_tags() would be extremely slow to
evaluate certain inputs containing large sequences of nested
incomplete HTML entities. The strip_tags() method is used to
implement the corresponding striptags template filter, which was
thus also vulnerable.

strip_tags() now avoids recursive calls to HTMLParser when
progress removing tags, but necessarily incomplete HTML entities,
stops being made.

Remember that absolutely NO guarantee is provided about the
results of strip_tags() being HTML safe. So NEVER mark safe the
result of a strip_tags() call without escaping it first, for
example with django.utils.html.escape().");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these has been fixed in python-django version
1.7.11-1+deb8u7.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.7.11-1+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-common", ver:"1.7.11-1+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1.7.11-1+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1.7.11-1+deb8u7", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);