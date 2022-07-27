# OpenVAS Vulnerability Test
# $Id: deb_2288_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2288-1 (libsndfile)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70061");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-07 17:37:07 +0200 (Sun, 07 Aug 2011)");
  script_cve_id("CVE-2011-2696");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 2288-1 (libsndfile)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202288-1");
  script_tag(name:"insight", value:"Hossein Lotfi discovered an integer overflow in libsndfile's code to
parse Paris Audio files, which could potentially lead to the execution
of arbitrary code.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.0.17-4+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.0.21-3+squeeze1

For the unstable distribution (sid), this problem has been fixed in
version 1.0.25-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your libsndfile packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to libsndfile
announced via advisory DSA 2288-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libsndfile1", ver:"1.0.17-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsndfile1-dev", ver:"1.0.17-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sndfile-programs", ver:"1.0.17-4+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsndfile1", ver:"1.0.21-3+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsndfile1-dev", ver:"1.0.21-3+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sndfile-programs", ver:"1.0.21-3+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}