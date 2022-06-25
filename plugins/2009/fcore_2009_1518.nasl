# OpenVAS Vulnerability Test
# $Id: fcore_2009_1518.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-1518 (python-fedora)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
tag_insight = "Update Information:

This release includes a bugfix to the
fedora.client.AccountSystem().verify_password() method.  verify_password() was
incorrectly returning True (username, password combination was correct) for any
input.  Although no known code is using this method to verify a user's account
with the Fedora Account System, the existence of the method and the fact that
anyone using this would be allowing users due to the bug makes this a high
priority bug to fix.

ChangeLog:

* Sun Feb  8 2009 Toshio Kuratomi  - 0.3.9-1
- New upstream with important bugfixes.
* Sat Nov 29 2008 Ignacio Vazquez-Abrams  - 0.3.8-2
- Rebuild for Python 2.6
* Thu Nov 20 2008 Toshio Kuratomi  - 0.3.8-1
- New upstream with pycurl client backend, more fas methods, and bodhi bugfix.
* Thu Oct 30 2008 Toshio Kuratomi  - 0.3.7-1
- New upstream has more complete pkgdb integration.";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update python-fedora' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1518";
tag_summary = "The remote host is missing an update to python-fedora
announced via advisory FEDORA-2009-1518.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309831");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Fedora Core 10 FEDORA-2009-1518 (python-fedora)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Fedora Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"python-fedora", rpm:"python-fedora~0.3.9~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
