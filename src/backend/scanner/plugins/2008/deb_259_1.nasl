# OpenVAS Vulnerability Test
# $Id: deb_259_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 259-1
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
tag_insight = "Florian Heinz <heinz@cronon-ag.de> posted to the Bugtraq mailing list an
exploit for qpopper based on a bug in the included vsnprintf implementation.
The sample exploit requires a valid user account and password, and overflows a
string in the pop_msg() function to give the user 'mail' group privileges and a
shell on the system. Since the Qvsnprintf function is used elsewhere in
qpopper, additional exploits may be possible.

The qpopper package in Debian 2.2 (potato) does not include the vulnerable
snprintf implementation. For Debian 3.0 (woody) an updated package is available
in version 4.0.4-2.woody.3. Users running an unreleased version of Debian
should upgrade to 4.0.4-9 or newer. We recommend you upgrade your qpopper
package immediately.";
tag_summary = "The remote host is missing an update to qpopper
announced via advisory DSA 259-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20259-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303254");
 script_version("$Revision: 6616 $");
 script_cve_id("CVE-2003-0143");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 259-1 (qpopper)");



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
if ((res = isdpkgvuln(pkg:"qpopper", ver:"4.0.4-2.woody.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qpopper-drac", ver:"4.0.4-2.woody.3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
