# OpenVAS Vulnerability Test
# $Id: deb_1505_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1505-1 (alsa-driver)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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

include("revisions-lib.inc");
tag_insight = "Takashi Iwai supplied a fix for a memory leak in the snd_page_alloc module.
Local users could exploit this issue to obtain sensitive information from
the kernel (CVE-2007-4571).

For the stable distribution (etch), this problem has been fixed in
version 1.0.13-5etch1. This issue was already fixed for the version
of ALSA provided by linux-2.6 in DSA 1479.

For the oldstable distribution (sarge), this problem has been fixed in
version 1.0.8-7sarge1. The prebuilt modules provided by alsa-modules-i386
have been rebuilt to take advantage of this update, and are available in
version 1.0.8+2sarge2.

For the unstable distributions (sid), this problem was fixed in version
1.0.15-1.

We recommend that you upgrade your alsa-driver and alsa-modules-i386";
tag_summary = "The remote host is missing an update to alsa-driver
announced via advisory DSA 1505-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201505-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302237");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-02-28 02:09:28 +0100 (Thu, 28 Feb 2008)");
 script_cve_id("CVE-2007-4571");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Debian Security Advisory DSA 1505-1 (alsa-driver)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"alsa-headers", ver:"1.0.8-7sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-source", ver:"1.0.8-7sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-base", ver:"1.0.8-7sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-386", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-686", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-386", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-k7-smp", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-k7-smp", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-686-smp", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-686-smp", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-686", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-k6", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-k7", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-k7", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-586tsc", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-586tsc", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-k6", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-source", ver:"1.0.13-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-base", ver:"1.0.13-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-sound-base", ver:"1.0.13-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
