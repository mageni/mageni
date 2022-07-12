# OpenVAS Vulnerability Test
# $Id: deb_967_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 967-1
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
version 2.5.7+r1558-4+sarge2.

For the unstable distribution (sid) these problems have been fixed in
version 2.6.1+r1642-1.

We recommend that you upgrade your elog package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20967-1";
tag_summary = "The remote host is missing an update to elog
announced via advisory DSA 967-1.

Several security problems have been found in elog, an electonic logbook
to manage notes.  The Common Vulnerabilities and Exposures Project
identifies the following problems:

CVE-2005-4439

GroundZero Security discovered that elog insufficiently checks the
size of a buffer used for processing URL parameters, which might lead
to the execution of arbitrary code.

CVE-2006-0347

It was discovered that elog contains a directory traveral vulnerability
in the processing of ../ sequences in URLs, which might lead to
information disclosure.

CVE-2006-0348

The code to write the log file contained a format string vulnerability,
which might lead to the execution of arbitrary code.

CVE-2006-0597

Overly long revision attributes might trigger a crash due to a buffer
overflow.

CVE-2006-0598

The code to write the log file does not enforce bounds checks properly,
which might lead to the execution of arbitrary code.

CVE-2006-0599

elog emitted different errors messages for invalid passwords and invalid
users, which allows an attacker to probe for valid user names.

CVE-2006-0600

An attacker could be driven into infinite redirection with a crafted
fail request, which has denial of service potential.

The old stable distribution (woody) does not contain elog packages.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301213");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-4439", "CVE-2006-0347", "CVE-2006-0348", "CVE-2006-0597", "CVE-2006-0598", "CVE-2006-0599", "CVE-2006-0600", "CVE-2005-4439");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 967-1 (elog)");



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
if ((res = isdpkgvuln(pkg:"elog", ver:"2.5.7+r1558-4+sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
