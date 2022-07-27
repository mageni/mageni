# OpenVAS Vulnerability Test
# $Id: deb_1627_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1627-1 (opensc)
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
tag_insight = "Chaskiel M Grundman discovered that opensc, a library and utilities to
handle smart cards, would initialise smart cards with the Siemens CardOS M4
card operating system without proper access rights. This allowed everyone
to change the card's PIN.

With this bug anyone can change a user PIN without having the PIN or PUK
or the superusers PIN or PUK. However it can not be used to figure out the
PIN. If the PIN on your card is still the same you always had, there's a
resonable chance that this vulnerability has not been exploited.

This vulnerability affects only smart cards and USB crypto tokens based on
Siemens CardOS M4, and within that group only those that were initialised
with OpenSC. Users of other smart cards and USB crypto tokens, or cards
that have been initialised with some software other than OpenSC, are not
affected.

After upgrading the package, running
pkcs15-tool -T
will show you whether the card is fine or vulnerable. If the card is
vulnerable, you need to update the security setting using:
pkcs15-tool -T -U

For the stable distribution (etch), this problem has been fixed in
version 0.11.1-2etch1.

For the unstable distribution (sid), this problem has been fixed in
version 0.11.4-4.

We recommend that you upgrade your opensc 0.11.1-2etch1 package and check";
tag_summary = "The remote host is missing an update to opensc
announced via advisory DSA 1627-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201627-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302855");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-08-15 15:52:52 +0200 (Fri, 15 Aug 2008)");
 script_cve_id("CVE-2008-2235");
 script_tag(name:"cvss_base", value:"4.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:N");
 script_name("Debian Security Advisory DSA 1627-1 (opensc)");



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
if ((res = isdpkgvuln(pkg:"opensc", ver:"0.11.1-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-opensc", ver:"0.11.1-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopensc2-dev", ver:"0.11.1-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopensc2-dbg", ver:"0.11.1-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopensc2", ver:"0.11.1-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
