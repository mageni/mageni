# OpenVAS Vulnerability Test
# $Id: deb_2354_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2354-1 (cups)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70568");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-2896", "CVE-2011-3170");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-11 02:32:46 -0500 (Sat, 11 Feb 2012)");
  script_name("Debian Security Advisory DSA 2354-1 (cups)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202354-1");
  script_tag(name:"insight", value:"Petr Sklenar and Tomas Hoger discovered that missing input sanitising in
the GIF decoder inside the Cups printing system could lead to denial
of service or potentially arbitrary code execution through crafted GIF
files.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.3.8-1+lenny10.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.4-7+squeeze1.

For the testing and unstable distribution (sid), this problem has been
fixed in version 1.5.0-8.");

  script_tag(name:"solution", value:"We recommend that you upgrade your cups packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to cups
announced via advisory DSA 2354-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"cups", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups-bsd", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups-client", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups-common", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups-dbg", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsys", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsys-bsd", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsys-client", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsys-common", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsys-dbg", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcups2", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcups2-dev", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsimage2", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsys2", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsys2-dev", ver:"1.3.8-1+lenny10", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups-bsd", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups-client", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups-common", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups-dbg", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups-ppdc", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsddk", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcups2", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcups2-dev", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupscgi1", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupscgi1-dev", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsdriver1", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsdriver1-dev", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsimage2", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsmime1", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsmime1-dev", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsppdc1", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsppdc1-dev", ver:"1.4.4-7+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}