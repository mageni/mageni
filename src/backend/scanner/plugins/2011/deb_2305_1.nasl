# OpenVAS Vulnerability Test
# $Id: deb_2305_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2305-1 (vsftpd)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70399");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2011-0762", "CVE-2011-2189");
  script_name("Debian Security Advisory DSA 2305-1 (vsftpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202305-1");
  script_tag(name:"insight", value:"Two security issue have been discovered that affect vsftpd, a lightweight,
efficient FTP server written for security.

CVE-2011-2189

It was discovered that Linux kernels < 2.6.35 are considerably slower in
releasing than in the creation of network namespaces.  As a result of this
and because vsftpd is using this feature as a security enhancement to
provide network isolation for connections, it is possible to cause denial
of service conditions due to excessive memory allocations by the kernel.
This is technically no vsftpd flaw, but a kernel issue.  However, this
feature has legitimate use cases and backporting the specific kernel patch
is too intrusive.  Additionally, a local attacker requires the CAP_SYS_ADMIN
capability to abuse this functionality.  Therefore, as a fix, a kernel
version check has been added to vsftpd in order to disable this feature
for kernels < 2.6.35.

CVE-2011-0762

Maksymilian Arciemowicz discovered that vsftpd is incorrectly handling
certain glob expressions in STAT commands.  This allows a remote authenticated
attacker to conduct denial of service attacks (excessive CPU and process
slot exhaustion) via crafted STAT commands.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.0.7-1+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 2.3.2-3+squeeze2.  Please note that CVE-2011-2189 does not affect
the lenny version.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 2.3.4-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your vsftpd packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to vsftpd
announced via advisory DSA 2305-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"vsftpd", ver:"2.0.7-1+lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vsftpd", ver:"2.3.2-3+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}