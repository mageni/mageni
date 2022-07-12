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
tag_insight = "The GdkPixbuf library, which is also included in GTK+ 2, contains several
vulnerabilities that could lead to a Denial of Service or the execution of
arbitrary code.";
tag_solution = "All GTK+ 2 users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=x11-libs/gtk+-2.4.9-r1'
    # emerge '>=x11-libs/gtk+-2.4.9-r1'

All GdkPixbuf users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=media-libs/gdk-pixbuf-0.22.0-r3'
    # emerge '>=media-libs/gdk-pixbuf-0.22.0-r3'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200409-28
http://bugs.gentoo.org/show_bug.cgi?id=64230
http://bugzilla.gnome.org/show_bug.cgi?id=150601";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200409-28.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304170");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2004-0753", "CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Gentoo Security Advisory GLSA 200409-28 (gtk+)");



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
if ((res = ispkgvuln(pkg:"x11-libs/gtk+", unaffected: make_list("ge 2.4.9-r1", "lt 2.0.0"), vulnerable: make_list("lt 2.4.9-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-libs/gdk-pixbuf", unaffected: make_list("ge 0.22.0-r3"), vulnerable: make_list("lt 0.22.0-r3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
