# OpenVAS Vulnerability Test
# $Id: deb_155_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 155-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
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
tag_insight = "Due to a security engineering oversight, the SSL library from KDE,
which Konqueror uses, doesn't check whether an intermediate
certificate for a connection is signed by the certificate authority as
safe for the purpose, but accepts it when it is signed.  This makes it
possible for anyone with a valid VeriSign SSL site certificate to
forge any other VeriSign SSL site certificate, and abuse Konqueror
users.

A local root exploit using artsd has been discovered which exploited
an insecure use of a format string.  The exploit wasn't working on a
Debian system since artsd wasn't running setuid root.  Neither artsd
nor artswrapper need to be setuid root anymore since current computer
systems are fast enuogh to handle the audio data in time.

These problems have been fixed in version 2.2.2-13.woody.2 for the
current stable stable distribution (woody).  The old stable
distribution (potato) is not affected, since it doesn't contain KDE
packages.  The unstable distribution (sid) is not yet fixed, but new
packages are expected in the future, the fixed version will be version
2.2.2-14 or higher.

We recommend that you upgrade your kdelibs and libarts packages and";
tag_summary = "The remote host is missing an update to kdelibs
announced via advisory DSA 155-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20155-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301099");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-0970");
 script_bugtraq_id(5410);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 155-1 (kdelibs)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"kdelibs3", ver:"2.2.2-13.woody.2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs3-bin", ver:"2.2.2-13.woody.2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libarts", ver:"2.2.2-13.woody.2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
