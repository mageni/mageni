# OpenVAS Vulnerability Test
# $Id: deb_1336_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1336-1
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
tag_insight = "Several remote vulnerabilities have been discovered in Mozilla Firefox.

This will be the last security update of Mozilla-based products for
the oldstable (sarge) distribution of Debian. We recommend to upgrade
to stable (etch) as soon as possible.

The Common Vulnerabilities and Exposures project identifies the following
vulnerabilities:

CVE-2007-1282

It was discovered that an integer overflow in text/enhanced message
parsing allows the execution of arbitrary code.

CVE-2007-0994

It was discovered that a regression in the Javascript engine allows
the execution of Javascript with elevated privileges.

CVE-2007-0995

It was discovered that incorrect parsing of invalid HTML characters
allows the bypass of content filters.

CVE-2007-0996

It was discovered that insecure child frame handling allows cross-site
scripting.

CVE-2007-0981

It was discovered that Firefox handles URI withs a null byte in the
hostname insecurely.

CVE-2007-0008

It was discovered that a buffer overflow in the NSS code allows the
execution of arbitrary code.

CVE-2007-0009

It was discovered that a buffer overflow in the NSS code allows the
execution of arbitrary code.

CVE-2007-0775

It was discovered that multiple programming errors in the layout engine
allow the execution of arbitrary code.

CVE-2007-0778

It was discovered that the page cache calculates hashes in an insecure
manner.

CVE-2006-6077

It was discovered that the password manager allows the disclosure of
passwords.

For the oldstable distribution (sarge) these problems have been fixed in
version 1.0.4-2sarge17. You should upgrade to etch as soon as possible.

The stable distribution (etch) isn't affected. These vulnerabilities have
been fixed prior to the release of Debian etch.

The unstable distribution (sid) no longer contains mozilla-firefox. Iceweasel
is already fixed.";
tag_summary = "The remote host is missing an update to mozilla-firefox
announced via advisory DSA 1336-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201336-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302746");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-1282", "CVE-2007-0994", "CVE-2007-0995", "CVE-2007-0996", "CVE-2007-0981", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0778", "CVE-2007-0045", "CVE-2006-6077");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1336-1 (mozilla-firefox)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.0.4-2sarge17", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"1.0.4-2sarge17", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"1.0.4-2sarge17", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
