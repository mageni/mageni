# OpenVAS Vulnerability Test
# $Id: deb_2643.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2643-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892643");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2013-2275", "CVE-2013-1652", "CVE-2013-1654", "CVE-2013-1653", "CVE-2013-1640", "CVE-2013-2274", "CVE-2013-1655");
  script_name("Debian Security Advisory DSA 2643-1 (puppet - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-12 00:00:00 +0100 (Tue, 12 Mar 2013)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2643.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"puppet on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), these problems have been fixed in
version 2.6.2-5+squeeze7.

For the testing distribution (wheezy), these problems have been fixed in
version 2.7.18-3.

For the unstable distribution (sid), these problems have been fixed in
version 2.7.18-3.

We recommend that you upgrade your puppet packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities were discovered in Puppet, a centralized
configuration management system.

CVE-2013-1640An authenticated malicious client may request its catalog from the puppet
master, and cause the puppet master to execute arbitrary code. The puppet
master must be made to invoke the template or inline_template

functions during catalog compilation.

CVE-2013-1652
An authenticated malicious client may retrieve catalogs from the puppet
master that it is not authorized to access. Given a valid certificate and
private key, it is possible to construct an HTTP GET request that will
return a catalog for an arbitrary client.

CVE-2013-1653An authenticated malicious client may execute arbitrary code on Puppet
agents that accept kick connections. Puppet agents are not vulnerable in
their default configuration. However, if the Puppet agent is configured to
listen for incoming connections, e.g. listen = true, and the agent's
auth.conf allows access to the run
REST endpoint, then an authenticated
client can construct an HTTP PUT request to execute arbitrary code on the
agent. This issue is made worse by the fact that puppet agents typically
run as root.

CVE-2013-1654
A bug in Puppet allows SSL connections to be downgraded to SSLv2, which is
known to contain design flaw weaknesses. This affects SSL connections
between puppet agents and master, as well as connections that puppet agents
make to third party servers that accept SSLv2 connections. Note that SSLv2
is disabled since OpenSSL 1.0.

CVE-2013-1655
An unauthenticated malicious client may send requests to the puppet master,
and have the master load code in an unsafe manner. It only affects users
whose puppet masters are running ruby 1.9.3 and above.

CVE-2013-2274
An authenticated malicious client may execute arbitrary code on the
puppet master in its default configuration. Given a valid certificate and
private key, a client can construct an HTTP PUT request that is authorized
to save the client's own report, but the request will actually cause the
puppet master to execute arbitrary code.

CVE-2013-2275
The default auth.conf allows an authenticated node to submit a report for
any other node, which is a problem for compliance. It has been made more
restrictive by default so that a node is only allowed to save its own
report.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"puppet", ver:"2.6.2-5+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet-common", ver:"2.6.2-5+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet-el", ver:"2.6.2-5+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet-testsuite", ver:"2.6.2-5+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppetmaster", ver:"2.6.2-5+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vim-puppet", ver:"2.6.2-5+squeeze7", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet", ver:"2.7.18-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet-common", ver:"2.7.18-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet-el", ver:"2.7.18-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet-testsuite", ver:"2.7.18-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppetmaster", ver:"2.7.18-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppetmaster-common", ver:"2.7.18-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppetmaster-passenger", ver:"2.7.18-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vim-puppet", ver:"2.7.18-3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}