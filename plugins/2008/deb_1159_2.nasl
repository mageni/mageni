# OpenVAS Vulnerability Test
# $Id: deb_1159_2.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1159-2
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
version 1.0.2-2.sarge1.0.8b.2.

For the unstable distribution (sid) these problems have been fixed in
version 1.5.0.5-1.

We recommend that you upgrade your mozilla-thunderbird package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201159-2";
tag_summary = "The remote host is missing an update to mozilla-thunderbird
announced via advisory DSA 1159-2.

The latest security updates of Mozilla Thunderbird introduced a
regression that led to a disfunctional attachment panel which warrants
a correction to fix this issue.  For reference please find below the
original advisory text:

Several security related problems have been discovered in Mozilla and
derived products such as Mozilla Thunderbird.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:

CVE-2006-2779

Mozilla team members discovered several crashes during testing of
the browser engine showing evidence of memory corruption which may
also lead to the execution of arbitrary code.  The last bit of
this problem will be corrected with the next update.  You can
prevent any trouble by disabling Javascript.  [MFSA-2006-32]

CVE-2006-3805

The Javascript engine might allow remote attackers to execute
arbitrary code.  [MFSA-2006-50]

CVE-2006-3806

Multiple integer overflows in the Javascript engine might allow
remote attackers to execute arbitrary code.  [MFSA-2006-50]

CVE-2006-3807

Specially crafted Javascript allows remote attackers to execute
arbitrary code.  [MFSA-2006-51]

CVE-2006-3808

Remote AutoConfig (PAC) servers could execute code with elevated
privileges via a specially crafted PAC script.  [MFSA-2006-52]

CVE-2006-3809

Scripts with the UniversalBrowserRead privilege could gain
UniversalXPConnect privileges and possibly execute code or obtain
sensitive data.  [MFSA-2006-53]

CVE-2006-3810

A cross-site scripting vulnerability allows remote attackers to
inject arbitrary web script or HTML.  [MFSA-2006-54]";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302219");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-2779", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810");
 script_bugtraq_id(18228,19181);
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1159-2 (mozilla-thunderbird)");



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
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.0.2-2.sarge1.0.8b.2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.0.2-2.sarge1.0.8b.2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.0.2-2.sarge1.0.8b.2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-offline", ver:"1.0.2-2.sarge1.0.8b.2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.0.2-2.sarge1.0.8b.2", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
