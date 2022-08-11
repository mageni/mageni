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
  script_oid("1.3.6.1.4.1.25623.1.0.892661");
  script_version("2021-05-15T03:00:41+0000");
  script_cve_id("CVE-2017-9735", "CVE-2018-12536", "CVE-2019-10241", "CVE-2019-10247", "CVE-2020-27216");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-05-17 10:34:03 +0000 (Mon, 17 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-15 03:00:41 +0000 (Sat, 15 May 2021)");
  script_name("Debian LTS: Security Advisory for jetty9 (DLA-2661-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00016.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2661-1");
  script_xref(name:"Advisory-ID", value:"DLA-2661-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/864898");
  script_xref(name:"URL", value:"https://bugs.debian.org/902774");
  script_xref(name:"URL", value:"https://bugs.debian.org/928444");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jetty9'
  package(s) announced via the DLA-2661-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in jetty, a Java servlet
engine and webserver. An attacker may reveal cryptographic credentials
such as passwords to a local user, disclose installation paths, hijack
user sessions or tamper with collocated webapps.

CVE-2017-9735

Jetty is prone to a timing channel in util/security/Password.java,
which makes it easier for remote attackers to obtain access by
observing elapsed times before rejection of incorrect passwords.

CVE-2018-12536

On webapps deployed using default Error Handling, when an
intentionally bad query arrives that doesn't match a dynamic
url-pattern, and is eventually handled by the DefaultServlet's
static file serving, the bad characters can trigger a
java.nio.file.InvalidPathException which includes the full path to
the base resource directory that the DefaultServlet and/or webapp
is using. If this InvalidPathException is then handled by the
default Error Handler, the InvalidPathException message is
included in the error response, revealing the full server path to
the requesting system.

CVE-2019-10241

The server is vulnerable to XSS conditions if a remote client USES
a specially formatted URL against the DefaultServlet or
ResourceHandler that is configured for showing a Listing of
directory contents.

CVE-2019-10247

The server running on any OS and Jetty version combination will
reveal the configured fully qualified directory base resource
location on the output of the 404 error for not finding a Context
that matches the requested path. The default server behavior on
jetty-distribution and jetty-home will include at the end of the
Handler tree a DefaultHandler, which is responsible for reporting
this 404 error, it presents the various configured contexts as
HTML for users to click through to. This produced HTML includes
output that contains the configured fully qualified directory base
resource location for each context.

CVE-2020-27216

On Unix like systems, the system's temporary directory is shared
between all users on that system. A collocated user can observe
the process of creating a temporary sub directory in the shared
temporary directory and race to complete the creation of the
temporary subdirectory. If the attacker wins the race then they
will have read and write permission to the subdirectory used to
unpack web applications, including their WEB-INF/lib jar files and
JSP files. If any code is ever executed out of this temporary
directory, this can lead to a local privilege escalation
vulnerability.

This update also includes several other bug fixes and
improvements. For more information please refer to the upstream
changelog file.");

  script_tag(name:"affected", value:"'jetty9' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
9.2.30-0+deb9u1.

We recommend that you upgrade your jetty9 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"jetty9", ver:"9.2.30-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjetty9-extra-java", ver:"9.2.30-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjetty9-java", ver:"9.2.30-0+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
