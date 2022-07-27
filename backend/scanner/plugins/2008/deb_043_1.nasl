# OpenVAS Vulnerability Test
# $Id: deb_043_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 043-1
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
tag_insight = "This advisory covers several vulnerabilities in Zope that have been
addressed.

1. Hotfix 08_09_2000 'Zope security alert and hotfix product'

The issue involves the fact that the getRoles method of user objects
contained in the default UserFolder implementation returns a mutable
Python type.  Because the mutable object is still associated with
the persistent User object, users with the ability to edit DTML
could arrange to give themselves extra roles for the duration of a
single request by mutating the roles list as a part of the request
processing.

2. Hotfix 2000-10-02 'ZPublisher security update'

It is sometimes possible to access, through an URL only, objects
protected by a role which the user has in some context, but not in
the context of the accessed object.

3. Hotfix 2000-10-11 'ObjectManager subscripting'

The issue involves the fact that the 'subscript notation' that can
be used to access items of ObjectManagers (Folders) did not
correctly restrict return values to only actual sub items.  This
made it possible to access names that should be private from DTML
(objects with names beginning with the underscore '_' character).
This could allow DTML authors to see private implementation data
structures and in certain cases possibly call methods that they
shouldn't have access to from DTML.

4. Hotfix 2001-02-23 'Class attribute access'

The issue is related to ZClasses in that a user with through-the-web
scripting capabilities on a Zope site can view and assign class
attributes to ZClasses, possibly allowing them to make inappropriate
changes to ZClass instances.

A second part fixes problems in the ObjectManager, PropertyManager,
and PropertySheet classes related to mutability of method return
values which could be perceived as a security problem.

We recommend you upgrade your zope package immediately.";
tag_summary = "The remote host is missing an update to zope
announced via advisory DSA 043-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20043-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303082");
 script_cve_id("CVE-2001-0568","CVE-2001-0569");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 043-1 (zope)");



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
if ((res = isdpkgvuln(pkg:"zope", ver:"2.1.6-7", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
