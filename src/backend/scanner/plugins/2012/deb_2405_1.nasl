# OpenVAS Vulnerability Test
# $Id: deb_2405_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2405-1 (apache2)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.70724");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2011-3607", "CVE-2011-3368", "CVE-2011-3639", "CVE-2011-4317", "CVE-2012-0031", "CVE-2012-0053");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-13 11:19:29 -0500 (Mon, 13 Feb 2012)");
  script_name("Debian Security Advisory DSA 2405-1 (apache2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202405-1");
  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Apache HTTPD Server:

CVE-2011-3607:

An integer overflow in ap_pregsub() could allow local attackers to
execute arbitrary code at elevated privileges via crafted .htaccess
files.

CVE-2011-3368 CVE-2011-3639 CVE-2011-4317:

The Apache HTTP Server did not properly validate the request URI for
proxied requests. In certain reverse proxy configurations using the
ProxyPassMatch directive or using the RewriteRule directive with the
[P] flag, a remote attacker could make the proxy connect to an
arbitrary server. The could allow the attacker to access internal
servers that are not otherwise accessible from the outside.

The three CVE ids denote slightly different variants of the same
issue.

Note that, even with this issue fixed, it is the responsibility of
the administrator to ensure that the regular expression replacement
pattern for the target URI does not allow a client to append arbitrary
strings to the host or port parts of the target URI. For example, the
configuration

ProxyPassMatch ^/mail(.*)  http://example.com$1

is still insecure and should be replaced by one of the following
configurations:

ProxyPassMatch ^/mail(/.*)  http://example.com$1
ProxyPassMatch ^/mail/(.*)  http://example.com/$1

CVE-2012-0031:

An apache2 child process could cause the parent process to crash
during shutdown. This is a violation of the privilege separation
between the apache2 processes and could potentially be used to worsen
the impact of other vulnerabilities.

CVE-2012-0053:

The response message for error code 400 (bad request) could be used to
expose httpOnly cookies. This could allow a remote attacker using
cross site scripting to steal authentication cookies.


For the oldstable distribution (lenny), these problems have been fixed in
version apache2 2.2.9-10+lenny12.

For the stable distribution (squeeze), these problems have been fixed in
version apache2 2.2.16-6+squeeze6

For the testing distribution (wheezy), these problems will be fixed in
version 2.2.22-1.

For the unstable distribution (sid), these problems have been fixed in
version 2.2.22-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your apache2 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to apache2
announced via advisory DSA 2405-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"apache2", ver:"2.2.9-10+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.2.9-10+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.9-10+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.9-10+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.9-10+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.9-10+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.9-10+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-src", ver:"2.2.9-10+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.9-10+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.9-10+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.9-10+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.9-10+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.9-10+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.16-6+squeeze6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.22-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}