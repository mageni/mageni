# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
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
tag_insight = "XDM will open TCP sockets for its chooser, even if the
DisplayManager.requestPort setting is set to 0. This may allow authorized
users to access a machine remotely via X, even if the administrator has
configured XDM to refuse such connections.";
tag_solution = "If you are using XFree86, you should run the following:

    # emerge sync

    # emerge -pv '>=x11-base/xfree-4.3.0-r6'
    # emerge '>=x11-base/xfree-4.3.0-r6'

If you are using X.org's X11 server, you should run the following:

    # emerge sync

    # emerge -pv '>=x11-base/xorg-x11-6.7.0-r1'
    # emerge '>=x11-base/xorg-x11-6.7.0-r1'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200407-05
http://bugs.gentoo.org/show_bug.cgi?id=53226
http://bugs.xfree86.org/show_bug.cgi?id=1376";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200407-05.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302590");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_bugtraq_id(10423);
 script_cve_id("CVE-2004-0419");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Gentoo Security Advisory GLSA 200407-05 (xdm)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Gentoo Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
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

include("pkg-lib-gentoo.inc");

res = "";
report = "";
if ((res = ispkgvuln(pkg:"x11-base/xfree", unaffected: make_list("ge 4.3.0-r6"), vulnerable: make_list("le 4.3.0-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-base/xorg-x11", unaffected: make_list("ge 6.7.0-r1"), vulnerable: make_list("le 6.7.0"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
