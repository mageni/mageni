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
  script_oid("1.3.6.1.4.1.25623.1.0.704422");
  script_version("2019-04-26T08:24:31+0000");
  script_cve_id("CVE-2018-17189", "CVE-2018-17199", "CVE-2019-0196", "CVE-2019-0211", "CVE-2019-0217", "CVE-2019-0220");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-04-26 08:24:31 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-06 02:00:17 +0000 (Sat, 06 Apr 2019)");
  script_name("Debian Security Advisory DSA 4422-1 (apache2 - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4422.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4422-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2'
  package(s) announced via the DSA-4422-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Apache HTTP server.

CVE-2018-17189
Gal Goldshtein of F5 Networks discovered a denial of service
vulnerability in mod_http2. By sending malformed requests, the
http/2 stream for that request unnecessarily occupied a server
thread cleaning up incoming data, resulting in denial of service.

CVE-2018-17199
Diego Angulo from ImExHS discovered that mod_session_cookie does not
respect expiry time.

CVE-2019-0196
Craig Young discovered that the http/2 request handling in mod_http2
could be made to access freed memory in string comparison when
determining the method of a request and thus process the request
incorrectly.

CVE-2019-0211
Charles Fol discovered a privilege escalation from the
less-privileged child process to the parent process running as root.

CVE-2019-0217
A race condition in mod_auth_digest when running in a threaded
server could allow a user with valid credentials to authenticate
using another username, bypassing configured access control
restrictions. The issue was discovered by Simon Kappel.

CVE-2019-0220
Bernhard Lorenz of Alpha Strike Labs GmbH reported that URL
normalizations were inconsistently handled. When the path component
of a request URL contains multiple consecutive slashes ('/'),
directives such as LocationMatch and RewriteRule must account for
duplicates in regular expressions while other aspects of the servers
processing will implicitly collapse them.");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 2.4.25-3+deb9u7.

This update also contains bug fixes that were scheduled for inclusion in the
next stable point release. This includes a fix for a regression caused by a
security fix in version 2.4.25-3+deb9u6.

We recommend that you upgrade your apache2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-data", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-dev", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-doc", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-ssl-dev", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec-pristine", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-utils", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);