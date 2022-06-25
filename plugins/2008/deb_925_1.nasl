# OpenVAS Vulnerability Test
# $Id: deb_925_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 925-1
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
version 2.0.13+1-6sarge2.

For the unstable distribution (sid) these problems have been fixed in
version 2.0.18-1.

We recommend that you upgrade your phpbb2 packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20925-1";
tag_summary = "The remote host is missing an update to phpbb2
announced via advisory DSA 925-1.

Several vulnerabilities have been discovered in phpBB, a fully
featured and skinnable flat webforum,

The Common Vulnerabilities and Exposures project identifies the
following problems:


CVE-2005-3310

Multiple interpretation errors allow remote authenticated users to
inject arbitrary web script when remote avatars and avatar
uploading are enabled.

CVE-2005-3415

phpBB allows remote attackers to bypass protection mechanisms that
deregister global variables that allows attackers to manipulate
the behaviour of phpBB.

CVE-2005-3416

phpBB allows remote attackers to bypass security checks when
register_globals is enabled and the session_start function has not
been called to handle a session.

CVE-2005-3417

phpBB allows remote attackers to modify global variables and
bypass security mechanisms.

CVE-2005-3418

Multiple cross-site scripting (XSS) vulnerabilities allow remote
attackers to inject arbitrary web scripts.

CVE-2005-3419

An SQL injection vulnerability allows remote attackers to execute
arbitrary SQL commands.

CVE-2005-3420

phpBB allows remote attackers to modify regular expressions and
execute PHP code via the signature_bbcode_uid parameter.

CVE-2005-3536

Missing input sanitising of the topic type allows remote attackers
to inject arbitrary SQL commands.

CVE-2005-3537

Missing request validation permitted remote attackers to edit
private messages of other users.

The old stable distribution (woody) does not contain phpbb2 packages.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303900");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-3310", "CVE-2005-3415", "CVE-2005-3416", "CVE-2005-3417", "CVE-2005-3418", "CVE-2005-3419", "CVE-2005-3420", "CVE-2005-3536", "CVE-2005-3537");
 script_bugtraq_id(15170,15243);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 925-1 (phpbb2)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"phpbb2-conf-mysql", ver:"2.0.13-6sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpbb2-languages", ver:"2.0.13-6sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpbb2", ver:"2.0.13-6sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
