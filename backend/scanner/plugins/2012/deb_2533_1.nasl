# OpenVAS Vulnerability Test
# $Id: deb_2533_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2533-1 (pcp)
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
  script_oid("1.3.6.1.4.1.25623.1.0.71821");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2012-3418", "CVE-2012-3419", "CVE-2012-3420", "CVE-2012-3421");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-08-30 11:32:31 -0400 (Thu, 30 Aug 2012)");
  script_name("Debian Security Advisory DSA 2533-1 (pcp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202533-1");
  script_tag(name:"insight", value:"It was discovered that Performance Co-Pilot (pcp), a framework for
performance monitoring, contains several vulnerabilities.

CVE-2012-3418
Multiple buffer overflows in the PCP protocol decoders can
cause PCP clients and servers to crash or, potentially,
execute arbitrary code while processing crafted PDUs.

CVE-2012-3419
The linux PMDA used by the pmcd daemon discloses sensitive
information from the /proc file system to unauthenticated
clients.

CVE-2012-3420
Multiple memory leaks processing crafted requests can cause
pmcd to consume large amounts of memory and eventually crash.

CVE-2012-3421
Incorrect event-driven programming allows malicious clients to
prevent other clients from accessing the pmcd daemon.

To address the information disclosure vulnerability, CVE-2012-3419, a
new proc PMDA was introduced, which is disabled by default.  If you
need access to this information, you need to enable the proc PMDA.

For the stable distribution (squeeze), this problem has been fixed in
version 3.3.3-squeeze2.

For the unstable distribution (sid), this problem has been fixed in
version 3.6.5.");

  script_tag(name:"solution", value:"We recommend that you upgrade your pcp packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to pcp
announced via advisory DSA 2533-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libpcp-gui2", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpcp-gui2-dev", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpcp-logsummary-perl", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpcp-mmv-perl", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpcp-mmv1", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpcp-mmv1-dev", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpcp-pmda-perl", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpcp-pmda3", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpcp-pmda3-dev", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpcp-trace2", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpcp-trace2-dev", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpcp3", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpcp3-dev", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pcp", ver:"3.3.3-squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}