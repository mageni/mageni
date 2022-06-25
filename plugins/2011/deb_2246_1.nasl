# OpenVAS Vulnerability Test
# $Id: deb_2246_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2246-1 (mahara)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.69743");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_cve_id("CVE-2011-1402", "CVE-2011-1403", "CVE-2011-1404", "CVE-2011-1405", "CVE-2011-1406");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 2246-1 (mahara)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202246-1");
  script_tag(name:"insight", value:"Several vulnerabilities were discovered in mahara, an electronic portfolio,
weblog, and resume builder. The following Common Vulnerabilities and
Exposures project ids identify them:


CVE-2011-1402

It was discovered that previous versions of Mahara did not check user
credentials before adding a secret URL to a view or suspending a user.


CVE-2011-1403

Due to a misconfiguration of the Pieform package in Mahara, the cross-site
request forgery protection mechanism that Mahara relies on to harden its
form was not working and was essentially disabled.
This is a critical vulnerability which could allow attackers to trick other
users (for example administrators) into performing malicious actions on
behalf of the attacker. Most Mahara forms are vulnerable.


CVE-2011-1404

Many of the JSON structures returned by Mahara for its AJAX interactions
included more information than what ought to be disclosed to the logged in
user. New versions of Mahara limit this information to what is necessary for
each page.


CVE-2011-1405

Previous versions of Mahara did not escape the contents of HTML emails sent
to users. Depending on the filters enabled in one's mail reader, it could
lead to cross-site scripting attacks.


CVE-2011-1406

It has been pointed out to us that if Mahara is configured (through its
wwwroot variable) to use HTTPS, it will happily let users login via the HTTP
version of the site if the web server is configured to serve content over
both protocol. The new version of Mahara will, when the wwwroot points to an
HTTPS URL, automatically redirect to HTTPS if it detects that it is being
run over HTTP.

We recommend that sites wanting to run Mahara over HTTPS make sure that
their web server configuration does not allow the serving of content over
HTTP and merely redirects to the secure version. We also suggest that site
administrators consider adding the HSTS headers to their web
server configuration.

For the oldstable distribution (lenny), these problems have been fixed in
version 1.0.4-4+lenny10.

For the stable distribution (squeeze), these problems have been fixed in
version 1.2.6-2+squeeze2.

For the testing distribution (wheezy), these problems have been fixed in
version 1.3.6-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.3.6-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your mahara packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to mahara
announced via advisory DSA 2246-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"mahara", ver:"1.0.4-4+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mahara-apache2", ver:"1.0.4-4+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mahara", ver:"1.2.6-2+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mahara-apache2", ver:"1.2.6-2+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mahara-mediaplayer", ver:"1.2.6-2+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mahara", ver:"1.3.6-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mahara-apache2", ver:"1.3.6-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mahara-mediaplayer", ver:"1.3.6-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}