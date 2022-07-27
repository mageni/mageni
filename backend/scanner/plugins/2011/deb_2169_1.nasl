# OpenVAS Vulnerability Test
# $Id: deb_2169_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2169-1 (telepathy-gabble)
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
  script_oid("1.3.6.1.4.1.25623.1.0.69002");
  script_cve_id("CVE-2011-1000");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("Debian Security Advisory DSA 2169-1 (telepathy-gabble)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202169-1");
  script_tag(name:"insight", value:"It was discovered that telepathy-gabble, the Jabber/XMMP connection manager
for the Telepathy framework, is processing google:jingleinfo updates without
validating their origin.  This may allow an attacker to trick telepathy-gabble
into relaying streamed media data through a server of his choice and thus
intercept audio and video calls.


For the oldstable distribution (lenny), this problem has been fixed in
version 0.7.6-1+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 0.9.15-1+squeeze1.

For the testing (wheezy) and unstable (sid) distributions, this problem
will be fixed soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your telepathy-gabble packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to telepathy-gabble
announced via advisory DSA 2169-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"telepathy-gabble", ver:"0.7.6-1+lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"telepathy-gabble-dbg", ver:"0.7.6-1+lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"telepathy-gabble", ver:"0.9.15-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"telepathy-gabble-dbg", ver:"0.9.15-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}