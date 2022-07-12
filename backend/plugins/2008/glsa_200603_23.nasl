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
tag_insight = "NetHack, Slash'EM and Falcon's Eye are vulnerable to local privilege
escalation vulnerabilities that could potentially allow the execution of
arbitrary code as other users.";
tag_solution = "NetHack has been masked in Portage pending the resolution of these issues.
Vulnerable NetHack users are advised to uninstall the package until
further notice.

    # emerge --ask --verbose --unmerge 'games-roguelike/nethack'

Slash'EM has been masked in Portage pending the resolution of these
issues. Vulnerable Slash'EM users are advised to uninstall the package
until further notice.

    # emerge --ask --verbose --unmerge 'games-roguelike/slashem'

Falcon's Eye has been masked in Portage pending the resolution of these
issues. Vulnerable Falcon's Eye users are advised to uninstall the package
until further notice.

    # emerge --ask --verbose --unmerge 'games-roguelike/falconseye'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200603-23
http://bugs.gentoo.org/show_bug.cgi?id=125902
http://bugs.gentoo.org/show_bug.cgi?id=122376
http://bugs.gentoo.org/show_bug.cgi?id=127167
http://bugs.gentoo.org/show_bug.cgi?id=127319";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200603-23.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301814");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_bugtraq_id(17217);
 script_cve_id("CVE-2006-1390");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Gentoo Security Advisory GLSA 200603-23 (nethack slashem falconseye)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
if ((res = ispkgvuln(pkg:"games-roguelike/nethack", unaffected: make_list(), vulnerable: make_list("le 3.4.3-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"games-roguelike/falconseye", unaffected: make_list(), vulnerable: make_list("le 1.9.4a"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"games-roguelike/slashem", unaffected: make_list(), vulnerable: make_list("le 0.0.760"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
