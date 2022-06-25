# OpenVAS Vulnerability Test
# $Id: deb_3346.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3346-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703346");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-6658", "CVE-2015-6659", "CVE-2015-6660", "CVE-2015-6661",
                  "CVE-2015-6665");
  script_name("Debian Security Advisory DSA 3346-1 (drupal7 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-08-31 00:00:00 +0200 (Mon, 31 Aug 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3346.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"drupal7 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 7.14-2+deb7u11.

For the stable distribution (jessie), these problems have been fixed in
version 7.32-1+deb8u5.

For the testing distribution (stretch), these problems have been fixed
in version 7.39-1.

For the unstable distribution (sid), these problems have been fixed in
version 7.39-1.

We recommend that you upgrade your drupal7 packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered
in Drupal, a content management framework:

CVE-2015-6658
The form autocomplete functionality did not properly sanitize the
requested URL, allowing remote attackers to perform a cross-site
scripting attack.

CVE-2015-6659
The SQL comment filtering system could allow a user with elevated
permissions to inject malicious code in SQL comments.

CVE-2015-6660
The form API did not perform form token validation early enough,
allowing the file upload callbacks to be run with untrusted input.
This could allow remote attackers to upload files to the site under
another user's account.

CVE-2015-6661Users without the access content
permission could see the titles
of nodes that they do not have access to, if the nodes were added to
a menu on the site that the users have access to.

CVE-2015-6665
Remote attackers could perform a cross-site scripting attack by
invoking Drupal.ajax() on a whitelisted HTML element.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"drupal7", ver:"7.14-2+deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}