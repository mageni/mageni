# OpenVAS Vulnerability Test
# $Id: deb_1191_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1191-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 1.0.2-2.sarge1.0.8c.1.

For the unstable distribution (sid) these problems have been fixed in
version 1.5.0.7-1.

We recommend that you upgrade your Mozilla Thunderbird packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201191-1";
tag_summary = "The remote host is missing an update to mozilla-thunderbird
announced via advisory DSA 1191-1.

Several security related problems have been discovered in Mozilla and
derived products such as Mozilla Thunderbird.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:

CVE-2006-2788

Fernando Ribeiro discovered that a vulnerability in the getRawDER
functionallows remote attackers to cause a denial of service
(hang) and possibly execute arbitrary code.

CVE-2006-4340

Daniel Bleichenbacher recently described an implementation error
in RSA signature verification that cause the application to
incorrectly trust SSL certificates.

CVE-2006-4565, CVE-2006-4566

Priit Laes reported that that a JavaScript regular expression can
trigger a heap-based buffer overflow which allows remote attackers
to cause a denial of service and possibly execute arbitrary code.

CVE-2006-4568

A vulnerability has been discovered that allows remote attackers
to bypass the security model and inject content into the sub-frame
of another site.

CVE-2006-4570

Georgi Guninski demonstrated that even with JavaScript disabled in
mail (the default) an attacker can still execute JavaScript when a
mail message is viewed, replied to, or forwarded.

CVE-2006-4571

Multiple unspecified vulnerabilities in Firefox, Thunderbird and
SeaMonkey allow remote attackers to cause a denial of service,
corrupt memory, and possibly execute arbitrary code.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301801");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-2788", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4568", "CVE-2006-4570", "CVE-2006-4571");
 script_bugtraq_id(20042);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1191-1 (mozilla-thunderbird)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.0.2-2.sarge1.0.8c.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.0.2-2.sarge1.0.8c.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.0.2-2.sarge1.0.8c.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-offline", ver:"1.0.2-2.sarge1.0.8c.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.0.2-2.sarge1.0.8c.1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
