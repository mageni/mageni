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
  script_oid("1.3.6.1.4.1.25623.1.0.891842");
  script_version("2019-07-02T02:00:06+0000");
  script_cve_id("CVE-2019-12781"); # nb: The mailing list entry is referring to a wrong CVE so the correct one was used here.
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-07-02 02:00:06 +0000 (Tue, 02 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-02 02:00:06 +0000 (Tue, 02 Jul 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1842-1] python-django security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00001.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1842-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/931316");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django'
  package(s) announced via the DSA-1842-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Django Python web development framework
did not correct identify HTTP connections when a reverse proxy
connected via HTTPS.

When deployed behind a reverse-proxy connecting to Django via HTTPS
django.http.HttpRequest.scheme would incorrectly detect client
requests made via HTTP as using HTTPS. This resulted in incorrect
results for is_secure(), and build_absolute_uri(), and that HTTP
requests would not be redirected to HTTPS in accordance with
SECURE_SSL_REDIRECT.

HttpRequest.scheme now respects SECURE_PROXY_SSL_HEADER, if it is
configured, and the appropriate header is set on the request, for
both HTTP and HTTPS requests.

If you deploy Django behind a reverse-proxy that forwards HTTP
requests, and that connects to Django via HTTPS, be sure to verify
that your application correctly handles code paths relying on scheme,
is_secure(), build_absolute_uri(), and SECURE_SSL_REDIRECT.");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this issue has been fixed in python-django version
1.7.11-1+deb8u6.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.7.11-1+deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-common", ver:"1.7.11-1+deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1.7.11-1+deb8u6", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1.7.11-1+deb8u6", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);