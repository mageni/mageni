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
  script_oid("1.3.6.1.4.1.25623.1.0.893000");
  script_version("2022-05-13T01:00:10+0000");
  script_cve_id("CVE-2019-16785", "CVE-2019-16786", "CVE-2019-16789", "CVE-2019-16792", "CVE-2022-24761");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-05-13 10:17:58 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-13 01:00:10 +0000 (Fri, 13 May 2022)");
  script_name("Debian LTS: Security Advisory for waitress (DLA-3000-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/05/msg00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3000-1");
  script_xref(name:"Advisory-ID", value:"DLA-3000-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1008013");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'waitress'
  package(s) announced via the DLA-3000-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Waitress is a Python WSGI server, an application server for Python web apps.

Security updates to fix request smuggling bugs, when combined with another http
proxy that interprets requests differently. This can lead to a potential for
HTTP request smuggling/splitting whereby Waitress may see two requests while
the front-end server only sees a single HTTP message. This can result in cache
poisoning or unexpected information disclosure.

CVE-2019-16785

Only recognise CRLF as a line-terminator, not a plain LF. Before this
change waitress could see two requests where the front-end proxy only saw
one.

CVE-2019-16786

Waitress would parse the Transfer-Encoding header and only look for a
single string value, if that value was not 'chunked' it would fall through
and use the Content-Length header instead. This could allow for Waitress
to treat a single request as multiple requests in the case of HTTP
pipelining.

CVE-2019-16789

Specially crafted requests containing special whitespace characters in the
Transfer-Encoding header would get parsed by Waitress as being a chunked
request, but a front-end server would use the Content-Length instead as the
Transfer-Encoding header is considered invalid due to containing invalid
characters. If a front-end server does HTTP pipelining to a backend
Waitress server this could lead to HTTP request splitting which may lead to
potential cache poisoning or unexpected information disclosure.

CVE-2019-16792

If two Content-Length headers are sent in a single request, Waitress would
treat the request as having no body, thereby treating the body of the
request as a new request in HTTP pipelining.

CVE-2022-24761

There are two classes of vulnerability that may lead to request smuggling
that are addressed by this advisory:
1. The use of Python's int() to parse strings into integers, leading to +10
to be parsed as 10, or 0x01 to be parsed as 1, where as the standard
specifies that the string should contain only digits or hex digits.
2. Waitress does not support chunk extensions, however it was discarding
them without validating that they did not contain illegal characters.");

  script_tag(name:"affected", value:"'waitress' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.0.1-1+deb9u1.

We recommend that you upgrade your waitress packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"python-waitress", ver:"1.0.1-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-waitress-doc", ver:"1.0.1-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-waitress", ver:"1.0.1-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
