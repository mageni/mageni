# OpenVAS Vulnerability Test
# $Id: deb_2549_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2549-1 (devscripts)
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
  script_oid("1.3.6.1.4.1.25623.1.0.72207");
  script_cve_id("CVE-2012-2240", "CVE-2012-2241", "CVE-2012-2242", "CVE-2012-3500");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-09-19 03:27:42 -0400 (Wed, 19 Sep 2012)");
  script_name("Debian Security Advisory DSA 2549-1 (devscripts)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202549-1");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in devscripts, a set of
scripts to make the life of a Debian Package maintainer easier.
The following Common Vulnerabilities and Exposures project ids have
been assigned to identify them:

CVE-2012-2240:

Raphael Geissert discovered that dscverify does not perform
sufficient validation and does not properly escape arguments to
external commands, allowing a remote attacker (as when dscverify is
used by dget) to execute arbitrary code.

CVE-2012-2241:

Raphael Geissert discovered that dget allows an attacker to delete
arbitrary files when processing a specially-crafted .dsc or
.changes file, due to insuficient input validation.

CVE-2012-2242:

Raphael Geissert discovered that dget does not properly escape
arguments to external commands when processing .dsc and .changes
files, allowing an attacker to execute arbitrary code.
This issue is limited with the fix for CVE-2012-2241, and had
already been fixed in version 2.10.73 due to changes to the code,
without considering its security implications.

CVE-2012-3500:

Jim Meyering, Red Hat, discovered that annotate-output determines
the name of temporary named pipes in a way that allows a local
attacker to make it abort, leading to denial of service.


Additionally, a regression in the exit code of debdiff introduced in
DSA-2409-1 has been fixed.

For the stable distribution (squeeze), these problems have been fixed in
version 2.10.69+squeeze4.

For the testing distribution (wheezy), these problems will be fixed
soon.

For the unstable distribution (sid), these problems will be fixed in
version 2.12.3.");

  script_tag(name:"solution", value:"We recommend that you upgrade your devscripts packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to devscripts
announced via advisory DSA 2549-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"devscripts", ver:"2.10.69+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}