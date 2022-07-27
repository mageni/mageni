# OpenVAS Vulnerability Test
# $Id: fcore_2008_11351.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2008-11351 (avahi)
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
tag_insight = "ChangeLog:

* Sun Dec 14 2008 Lennart Poettering  - 0.6.22-12
- Fix a couple of issues, rhbz #475394, avahi bts #209, rhbz #438013, avahi bts
All backported from upstream 0.6.24";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update avahi' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2008-11351";
tag_summary = "The remote host is missing an update to avahi
announced via advisory FEDORA-2008-11351.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307561");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-01-07 23:16:01 +0100 (Wed, 07 Jan 2009)");
 script_cve_id("CVE-2008-5081");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Fedora Core 10 FEDORA-2008-11351 (avahi)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=475964");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-autoipd", rpm:"avahi-autoipd~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-compat-howl", rpm:"avahi-compat-howl~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-compat-howl", rpm:"avahi-compat-howl~devel~0.6.22", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-compat-libdns_sd", rpm:"avahi-compat-libdns_sd~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-compat-libdns_sd", rpm:"avahi-compat-libdns_sd~devel~0.6.22", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-devel", rpm:"avahi-devel~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-dnsconfd", rpm:"avahi-dnsconfd~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-glib", rpm:"avahi-glib~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-glib-devel", rpm:"avahi-glib-devel~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-gobject", rpm:"avahi-gobject~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-gobject-devel", rpm:"avahi-gobject-devel~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-qt3", rpm:"avahi-qt3~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-qt3-devel", rpm:"avahi-qt3-devel~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-qt4", rpm:"avahi-qt4~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-qt4-devel", rpm:"avahi-qt4-devel~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-sharp", rpm:"avahi-sharp~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-tools", rpm:"avahi-tools~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-ui", rpm:"avahi-ui~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-ui-devel", rpm:"avahi-ui-devel~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-ui-sharp", rpm:"avahi-ui-sharp~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-ui-tools", rpm:"avahi-ui-tools~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-debuginfo", rpm:"avahi-debuginfo~0.6.22~12.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
