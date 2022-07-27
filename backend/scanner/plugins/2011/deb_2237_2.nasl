# OpenVAS Vulnerability Test
# $Id: deb_2237_2.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2237-2 (apr)
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
  script_oid("1.3.6.1.4.1.25623.1.0.69737");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2011-0419", "CVE-2011-1928");
  script_name("Debian Security Advisory DSA 2237-2 (apr)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202237-2");
  script_tag(name:"insight", value:"The recent APR update DSA-2237-1 introduced a regression that could
lead to an endless loop in the apr_fnmatch() function, causing a
denial of service. This update fixes this problem (CVE-2011-1928).

For reference, the description of the original DSA, which fixed
CVE-2011-0419:

A flaw was found in the APR library, which could be exploited through
Apache HTTPD's mod_autoindex.  If a directory indexed by mod_autoindex
contained files with sufficiently long names, a remote attacker could
send a carefully crafted request which would cause excessive CPU
usage. This could be used in a denial of service attack.


For the oldstable distribution (lenny), this problem has been fixed in
version 1.2.12-5+lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.2-6+squeeze2.

For the testing distribution (wheezy), this problem will be fixed in
version 1.4.5-1.

For the unstable distribution (sid), this problem will be fixed in
version 1.4.5-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your apr packages and restart the");
  script_tag(name:"summary", value:"The remote host is missing an update to apr
announced via advisory DSA 2237-2.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapr1", ver:"1.2.12-5+lenny4", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapr1-dbg", ver:"1.2.12-5+lenny4", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapr1-dev", ver:"1.2.12-5+lenny4", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapr1", ver:"1.4.2-6+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapr1-dbg", ver:"1.4.2-6+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapr1-dev", ver:"1.4.2-6+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapr1", ver:"1.4.5-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapr1-dbg", ver:"1.4.5-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapr1-dev", ver:"1.4.5-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}