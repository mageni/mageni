# OpenVAS Vulnerability Test
# $Id: deb_2323_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2323-1 (radvd)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70546");
  script_cve_id("CVE-2011-3602", "CVE-2011-3604", "CVE-2011-3605");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-11 02:27:04 -0500 (Sat, 11 Feb 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 2323-1 (radvd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202323-1");
  script_tag(name:"insight", value:"Multiple security issues were discovered by Vasiliy Kulikov in radvd, an
IPv6 Router Advertisement daemon:

CVE-2011-3602

set_interface_var() function doesn't check the interface name, which is
chosen by an unprivileged user. This could lead to an arbitrary file
overwrite if the attacker has local access, or specific files overwrites
otherwise.

CVE-2011-3604

process_ra() function lacks multiple buffer length checks which could
lead to memory reads outside the stack, causing a crash of the daemon.

CVE-2011-3605

process_rs() function calls mdelay() (a function to wait for a defined
time) unconditionally when running in unicast-only mode. As this call
is in the main thread, that means all request processing is delayed (for
a time up to MAX_RA_DELAY_TIME, 500 ms by default). An attacked could
flood the daemon with router solicitations in order to fill the input
queue, causing a temporary denial of service (processing would be
stopped during all the mdelay() calls).
Note: upstream and Debian default is to use anycast mode.


For the oldstable distribution (lenny), this problem has been fixed in
version 1:1.1-3.1.

For the stable distribution (squeeze), this problem has been fixed in
version 1:1.6-1.1.

For the testing distribution (wheezy), this problem has been fixed in
version 1:1.8-1.2.

For the unstable distribution (sid), this problem has been fixed in
version 1:1.8-1.2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your radvd packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to radvd
announced via advisory DSA 2323-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"radvd", ver:"1:1.1-3.1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"radvd", ver:"1:1.6-1.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"radvd", ver:"1:1.8-1.2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}