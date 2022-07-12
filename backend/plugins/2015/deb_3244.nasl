# OpenVAS Vulnerability Test
# $Id: deb_3244.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3244-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703244");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-3011", "CVE-2015-3012", "CVE-2015-3013");
  script_name("Debian Security Advisory DSA 3244-1 (owncloud - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-05-02 00:00:00 +0200 (Sat, 02 May 2015)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3244.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"owncloud on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), these problems have been fixed in
version 7.0.4+dfsg-4~deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 7.0.4+dfsg-3.

For the unstable distribution (sid), these problems have been fixed in
version 7.0.4+dfsg-3.

We recommend that you upgrade your owncloud packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities were discovered in ownCloud, a cloud storage
web service for files, music, contacts, calendars and many more.

CVE-2015-3011Hugh Davenport discovered that the contacts
application shipped
with ownCloud is vulnerable to multiple stored cross-site
scripting attacks. This vulnerability is effectively exploitable
in any browser.

CVE-2015-3012Roy Jansen discovered that the documents
application shipped with
ownCloud is vulnerable to multiple stored cross-site scripting
attacks. This vulnerability is not exploitable in browsers that
support the current CSP standard.

CVE-2015-3013
Lukas Reschke discovered a blacklist bypass vulnerability, allowing
authenticated remote attackers to bypass the file blacklist and
upload files such as the .htaccess files. An attacker could leverage
this bypass by uploading a .htaccess and execute arbitrary PHP code
if the /data/ directory is stored inside the web root and a web
server that interprets .htaccess files is used. On default Debian
installations the data directory is outside of the web root and thus
this vulnerability is not exploitable by default.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"owncloud", ver:"7.0.4+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"owncloud", ver:"7.0.4+dfsg-4~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}