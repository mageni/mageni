# OpenVAS Vulnerability Test
# $Id: deb_158_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 158-1
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
tag_insight = "The developers of Gaim, an instant messenger client that combines
several different networks, found a vulnerability in the hyperlink
handling code.  The 'Manual' browser command passes an untrusted
string to the shell without escaping or reliable quoting, permitting
an attacker to execute arbitrary commands on the users machine.
Unfortunately, Gaim doesn't display the hyperlink before the user
clicks on it.  Users who use other inbuilt browser commands aren't
vulnerable.

This problem has been fixed in version 0.58-2.2 for the current
stable distribution (woody) and in version 0.59.1-2 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected since it doesn't ship the Gaim program.

The fixed version of Gaim no longer passes the user's manual browser
command to the shell.  Commands which contain the %s in quotes will
need to be amended, so they don't contain any quotes.  The 'Manual'
browser command can be edited in the 'General' pane of the
'Preferences' dialog, which can be accessed by clicking 'Options' from
the login window, or 'Tools' and then 'Preferences' from the menu bar
in the buddy list window.

We recommend that you upgrade your gaim package immediately.";
tag_summary = "The remote host is missing an update to gaim
announced via advisory DSA 158-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20158-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302328");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-0989");
 script_bugtraq_id(5574);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 158-1 (gaim)");



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
if ((res = isdpkgvuln(pkg:"gaim", ver:"0.58-2.2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gaim-common", ver:"0.58-2.2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gaim-gnome", ver:"0.58-2.2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
