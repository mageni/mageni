# OpenVAS Vulnerability Test
# $Id: mdksa_2009_031.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:031 (avahi)
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
tag_insight = "A vulnerability has been discovered in Avahi before 0.6.24, which
allows remote attackers to cause a denial of service (crash) via a
crafted mDNS packet with a source port of 0 (CVE-2008-5081).

The updated packages have been patched to prevent this.

Affected: 2008.0, 2008.1, 2009.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:031";
tag_summary = "The remote host is missing an update to avahi
announced via advisory MDVSA-2009:031.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307176");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-02-02 23:28:24 +0100 (Mon, 02 Feb 2009)");
 script_cve_id("CVE-2008-5081");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:031 (avahi)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-dnsconfd", rpm:"avahi-dnsconfd~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-python", rpm:"avahi-python~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-sharp", rpm:"avahi-sharp~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-sharp-doc", rpm:"avahi-sharp-doc~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-x11", rpm:"avahi-x11~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-client3-devel", rpm:"libavahi-client3-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-common3-devel", rpm:"libavahi-common3-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-compat-howl0", rpm:"libavahi-compat-howl0~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-compat-howl0-devel", rpm:"libavahi-compat-howl0-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd1", rpm:"libavahi-compat-libdns_sd1~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd1-devel", rpm:"libavahi-compat-libdns_sd1-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-core5", rpm:"libavahi-core5~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-core5-devel", rpm:"libavahi-core5-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-glib1-devel", rpm:"libavahi-glib1-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-qt3_1", rpm:"libavahi-qt3_1~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-qt3_1-devel", rpm:"libavahi-qt3_1-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-qt4_1", rpm:"libavahi-qt4_1~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-qt4_1-devel", rpm:"libavahi-qt4_1-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-ui1", rpm:"libavahi-ui1~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-ui1-devel", rpm:"libavahi-ui1-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-client3", rpm:"lib64avahi-client3~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-client3-devel", rpm:"lib64avahi-client3-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-common3", rpm:"lib64avahi-common3~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-common3-devel", rpm:"lib64avahi-common3-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl0", rpm:"lib64avahi-compat-howl0~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl0-devel", rpm:"lib64avahi-compat-howl0-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd1", rpm:"lib64avahi-compat-libdns_sd1~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd1-devel", rpm:"lib64avahi-compat-libdns_sd1-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-core5", rpm:"lib64avahi-core5~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-core5-devel", rpm:"lib64avahi-core5-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-glib1", rpm:"lib64avahi-glib1~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-glib1-devel", rpm:"lib64avahi-glib1-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-qt3_1", rpm:"lib64avahi-qt3_1~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-qt3_1-devel", rpm:"lib64avahi-qt3_1-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-qt4_1", rpm:"lib64avahi-qt4_1~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-qt4_1-devel", rpm:"lib64avahi-qt4_1-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-ui1", rpm:"lib64avahi-ui1~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-ui1-devel", rpm:"lib64avahi-ui1-devel~0.6.21~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-dnsconfd", rpm:"avahi-dnsconfd~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-python", rpm:"avahi-python~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-sharp", rpm:"avahi-sharp~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-sharp-doc", rpm:"avahi-sharp-doc~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-x11", rpm:"avahi-x11~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-client-devel", rpm:"libavahi-client-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-common-devel", rpm:"libavahi-common-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-compat-howl0", rpm:"libavahi-compat-howl0~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-compat-howl-devel", rpm:"libavahi-compat-howl-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd1", rpm:"libavahi-compat-libdns_sd1~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd-devel", rpm:"libavahi-compat-libdns_sd-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-core5", rpm:"libavahi-core5~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-core-devel", rpm:"libavahi-core-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-glib-devel", rpm:"libavahi-glib-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-gobject0", rpm:"libavahi-gobject0~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-gobject-devel", rpm:"libavahi-gobject-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-qt3_1", rpm:"libavahi-qt3_1~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-qt3-devel", rpm:"libavahi-qt3-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-qt4_1", rpm:"libavahi-qt4_1~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-qt4-devel", rpm:"libavahi-qt4-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-ui1", rpm:"libavahi-ui1~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-ui-devel", rpm:"libavahi-ui-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-client3", rpm:"lib64avahi-client3~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-client-devel", rpm:"lib64avahi-client-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-common3", rpm:"lib64avahi-common3~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-common-devel", rpm:"lib64avahi-common-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl0", rpm:"lib64avahi-compat-howl0~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl-devel", rpm:"lib64avahi-compat-howl-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd1", rpm:"lib64avahi-compat-libdns_sd1~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd-devel", rpm:"lib64avahi-compat-libdns_sd-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-core5", rpm:"lib64avahi-core5~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-core-devel", rpm:"lib64avahi-core-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-glib1", rpm:"lib64avahi-glib1~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-glib-devel", rpm:"lib64avahi-glib-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-gobject0", rpm:"lib64avahi-gobject0~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-gobject-devel", rpm:"lib64avahi-gobject-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-qt3_1", rpm:"lib64avahi-qt3_1~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-qt3-devel", rpm:"lib64avahi-qt3-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-qt4_1", rpm:"lib64avahi-qt4_1~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-qt4-devel", rpm:"lib64avahi-qt4-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-ui1", rpm:"lib64avahi-ui1~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-ui-devel", rpm:"lib64avahi-ui-devel~0.6.22~3.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-dnsconfd", rpm:"avahi-dnsconfd~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-python", rpm:"avahi-python~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-sharp", rpm:"avahi-sharp~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-sharp-doc", rpm:"avahi-sharp-doc~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-x11", rpm:"avahi-x11~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-client-devel", rpm:"libavahi-client-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-common-devel", rpm:"libavahi-common-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-compat-howl0", rpm:"libavahi-compat-howl0~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-compat-howl-devel", rpm:"libavahi-compat-howl-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd1", rpm:"libavahi-compat-libdns_sd1~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-compat-libdns_sd-devel", rpm:"libavahi-compat-libdns_sd-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-core5", rpm:"libavahi-core5~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-core-devel", rpm:"libavahi-core-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-glib-devel", rpm:"libavahi-glib-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-gobject0", rpm:"libavahi-gobject0~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-gobject-devel", rpm:"libavahi-gobject-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-qt3_1", rpm:"libavahi-qt3_1~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-qt3-devel", rpm:"libavahi-qt3-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-qt4_1", rpm:"libavahi-qt4_1~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-qt4-devel", rpm:"libavahi-qt4-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-ui1", rpm:"libavahi-ui1~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavahi-ui-devel", rpm:"libavahi-ui-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-client3", rpm:"lib64avahi-client3~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-client-devel", rpm:"lib64avahi-client-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-common3", rpm:"lib64avahi-common3~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-common-devel", rpm:"lib64avahi-common-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl0", rpm:"lib64avahi-compat-howl0~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-compat-howl-devel", rpm:"lib64avahi-compat-howl-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd1", rpm:"lib64avahi-compat-libdns_sd1~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-compat-libdns_sd-devel", rpm:"lib64avahi-compat-libdns_sd-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-core5", rpm:"lib64avahi-core5~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-core-devel", rpm:"lib64avahi-core-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-glib1", rpm:"lib64avahi-glib1~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-glib-devel", rpm:"lib64avahi-glib-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-gobject0", rpm:"lib64avahi-gobject0~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-gobject-devel", rpm:"lib64avahi-gobject-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-qt3_1", rpm:"lib64avahi-qt3_1~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-qt3-devel", rpm:"lib64avahi-qt3-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-qt4_1", rpm:"lib64avahi-qt4_1~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-qt4-devel", rpm:"lib64avahi-qt4-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-ui1", rpm:"lib64avahi-ui1~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avahi-ui-devel", rpm:"lib64avahi-ui-devel~0.6.23~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
