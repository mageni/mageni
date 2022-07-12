# OpenVAS Vulnerability Test
# $Id: deb_999_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 999-1
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
version 1.2-5sarge1.

For the unstable distribution (sid) these problems have been fixed in
version 2.1-1.

We recommend that you upgrade your lurker package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20999-1";
tag_summary = "The remote host is missing an update to lurker
announced via advisory DSA 999-1.

Several security related problems have been discovered in lurker, an
archive tool for mailing lists with integrated search engine.  The
Common Vulnerability and Exposures project identifies the following
problems:

CVE-2006-1062

Lurker's mechanism for specifying configuration files was
vulnerable to being overridden.  As lurker includes sections of
unparsed config files in its output, an attacker could manipulate
lurker into reading any file readable by the www-data user.

CVE-2006-1063

It is possible for a remote attacker to create or overwrite files
in any writable directory that is named mbox.

CVE-2006-1064

Missing input sanitising allows an attacker to inject arbitrary
web script or HTML.

The old stable distribution (woody) does not contain lurker packages.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302486");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-1062", "CVE-2006-1063", "CVE-2006-1064");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Debian Security Advisory DSA 999-1 (lurker)");



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
if ((res = isdpkgvuln(pkg:"lurker", ver:"1.2-5sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
