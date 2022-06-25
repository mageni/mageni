# OpenVAS Vulnerability Test
# $Id: deb_2281_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2281-1 (opie)
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
  script_oid("1.3.6.1.4.1.25623.1.0.69990");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-2489", "CVE-2011-2490", "CVE-2010-1938");
  script_name("Debian Security Advisory DSA 2281-1 (opie)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202281-1");
  script_tag(name:"insight", value:"Sebastian Krahmer discovered that opie, a system that makes it simple to
use One-Time passwords in applications, is prone to a privilege
escalation (CVE-2011-2490) and an off-by-one error, which can lead to
the execution of arbitrary code (CVE-2011-2489). Adam Zabrocki and
Maksymilian Arciemowicz also discovered another off-by-one error
(CVE-2010-1938), which only affects the lenny version as the fix was
already included for squeeze.


For the oldstable distribution (lenny), these problems have been fixed in
version 2.32-10.2+lenny2.

For the stable distribution (squeeze), these problems have been fixed in
version 2.32.dfsg.1-0.2+squeeze1

The testing distribution (wheezy) and the unstable distribution (sid) do
not contain opie.");

  script_tag(name:"solution", value:"We recommend that you upgrade your opie packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to opie
announced via advisory DSA 2281-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libopie-dev", ver:"2.32-10.2+lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"opie-client", ver:"2.32-10.2+lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"opie-server", ver:"2.32-10.2+lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopie-dev", ver:"2.32.dfsg.1-0.2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"opie-client", ver:"2.32.dfsg.1-0.2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"opie-server", ver:"2.32.dfsg.1-0.2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}