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
tag_insight = "X.org, libX11, xdm, xf86dga, xinit, xload, xtrans, and xterm are vulnerable
to local privilege escalations because of unchecked setuid() calls.";
tag_solution = "All X.Org xdm users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-apps/xdm-1.0.4-r1'

All X.Org xinit users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-apps/xinit-1.0.2-r6'

All X.Org xload users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-apps/xload-1.0.1-r1'

All X.Org xf86dga users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-apps/xf86dga-1.0.1-r1'

All X.Org users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-base/xorg-x11-6.9.0-r2'

All X.Org X servers users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-base/xorg-server-1.1.0-r1'

All X.Org X11 library users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/libx11-1.0.1-r1'

All X.Org xtrans library users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/xtrans-1.0.1-r1'

All xterm users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/xterm-215'

All users of the X11R6 libraries for emulation of 32bit x86 on amd64
should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=app-emulation/emul-linux-x86-xlibs-7.0-r2'

Please note that the fixed packages have been available for most
architectures since June 30th but the GLSA release was held up waiting for
the remaining architectures.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200608-25
http://bugs.gentoo.org/show_bug.cgi?id=135974
http://lists.freedesktop.org/archives/xorg/2006-June/016146.html";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200608-25.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301468");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2006-4447");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Gentoo Security Advisory GLSA 200608-25 (xorg-x11,xorg-server,xtrans,xload,xinit,xterm,xf86dga,xdm,libX11)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = ispkgvuln(pkg:"x11-apps/xdm", unaffected: make_list("ge 1.0.4-r1"), vulnerable: make_list("lt 1.0.4-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-apps/xinit", unaffected: make_list("ge 1.0.2-r6"), vulnerable: make_list("lt 1.0.2-r6"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-apps/xload", unaffected: make_list("ge 1.0.1-r1"), vulnerable: make_list("lt 1.0.1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-apps/xf86dga", unaffected: make_list("ge 1.0.1-r1"), vulnerable: make_list("lt 1.0.1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-base/xorg-x11", unaffected: make_list("rge 6.8.2-r8", "ge 6.9.0-r2"), vulnerable: make_list("lt 6.9.0-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-base/xorg-server", unaffected: make_list("rge 1.0.2-r6", "ge 1.1.0-r1"), vulnerable: make_list("lt 1.1.0-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-libs/libx11", unaffected: make_list("ge 1.0.1-r1"), vulnerable: make_list("lt 1.0.1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-libs/xtrans", unaffected: make_list("ge 1.0.0-r1"), vulnerable: make_list("lt 1.0.0-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-terms/xterm", unaffected: make_list("ge 215"), vulnerable: make_list("lt 215"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-emulation/emul-linux-x86-xlibs", unaffected: make_list("ge 7.0-r2"), vulnerable: make_list("lt 7.0-r2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
