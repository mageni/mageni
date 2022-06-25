# OpenVAS Vulnerability Test
# $Id: suse_sr_2009_001b.nasl 6668 2017-07-11 13:34:29Z cfischer $
# Description: Auto-generated from advisory SUSE-SR:2009:001
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
tag_summary = "The remote host is missing updates announced in
advisory SUSE-SR:2009:001.  SuSE Security Summaries are short
on detail when it comes to the names of packages affected by
a particular bug. Because of this, while this test will detect
out of date packages, it cannot tell you what bugs impact
which packages, or vice versa.";

tag_solution = "Update all out of date packages.";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310976");
 script_version("$Revision: 6668 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:34:29 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
 script_cve_id("CVE-2008-2380", "CVE-2008-3933", "CVE-2008-3934", "CVE-2008-3963", "CVE-2008-4097", "CVE-2008-4098", "CVE-2008-4225", "CVE-2008-4314", "CVE-2008-4552", "CVE-2008-4575", "CVE-2008-4639", "CVE-2008-4640", "CVE-2008-4641", "CVE-2008-4680", "CVE-2008-4681", "CVE-2008-4682", "CVE-2008-4683", "CVE-2008-4684", "CVE-2008-4685", "CVE-2008-4864", "CVE-2008-5006", "CVE-2008-5031", "CVE-2008-5285", "CVE-2008-5514", "CVE-2008-5517", "CVE-2008-5617", "CVE-2008-5618", "CVE-2009-0022", "CVE-2008-5660");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("SuSE Security Summary SUSE-SR:2009:001 (OpenSuSE 10.3)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.1.8~20.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.1.8~20.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.3.5.10~2.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.3.5.10~2.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~6.3.5.10~2.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~2.0.0.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations", rpm:"MozillaThunderbird-translations~2.0.0.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"NX", rpm:"NX~2.1.0~35.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~0.6.5~37.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"NetworkManager-devel", rpm:"NetworkManager-devel~0.6.5~37.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~0.6.5~37.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"NetworkManager-gnome", rpm:"NetworkManager-gnome~0.6.5~37.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-base", rpm:"OpenOffice_org-base~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-calc", rpm:"OpenOffice_org-calc~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-devel", rpm:"OpenOffice_org-devel~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-draw", rpm:"OpenOffice_org-draw~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-filters", rpm:"OpenOffice_org-filters~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-impress", rpm:"OpenOffice_org-impress~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-mailmerge", rpm:"OpenOffice_org-mailmerge~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-math", rpm:"OpenOffice_org-math~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-officebean", rpm:"OpenOffice_org-officebean~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-pyuno", rpm:"OpenOffice_org-pyuno~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-sdk", rpm:"OpenOffice_org-sdk~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-sdk-doc", rpm:"OpenOffice_org-sdk-doc~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-testtool", rpm:"OpenOffice_org-testtool~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenOffice_org-writer", rpm:"OpenOffice_org-writer~2.3.0.1.2~10.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"SDL_image", rpm:"SDL_image~1.2.6~25.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"SDL_image-devel", rpm:"SDL_image-devel~1.2.6~25.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"aaa_base", rpm:"aaa_base~10.3~90.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acerhk-kmp-bigsmp", rpm:"acerhk-kmp-bigsmp~0.5.35_2.6.22.18_0.2~28.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acerhk-kmp-debug", rpm:"acerhk-kmp-debug~0.5.35_2.6.22.18_0.2~28.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acerhk-kmp-default", rpm:"acerhk-kmp-default~0.5.35_2.6.22.18_0.2~28.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acerhk-kmp-xen", rpm:"acerhk-kmp-xen~0.5.35_2.6.22.18_0.2~28.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acerhk-kmp-xenpae", rpm:"acerhk-kmp-xenpae~0.5.35_2.6.22.18_0.2~28.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.3~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acx-kmp-bigsmp", rpm:"acx-kmp-bigsmp~20070101_2.6.22.18_0.2~5.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acx-kmp-debug", rpm:"acx-kmp-debug~20070101_2.6.22.18_0.2~5.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acx-kmp-default", rpm:"acx-kmp-default~20070101_2.6.22.18_0.2~5.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acx-kmp-xen", rpm:"acx-kmp-xen~20070101_2.6.22.18_0.2~5.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acx-kmp-xenpae", rpm:"acx-kmp-xenpae~20070101_2.6.22.18_0.2~5.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"adm8211-kmp-bigsmp", rpm:"adm8211-kmp-bigsmp~20070720_2.6.22.18_0.2~2.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"adm8211-kmp-debug", rpm:"adm8211-kmp-debug~20070720_2.6.22.18_0.2~2.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"adm8211-kmp-default", rpm:"adm8211-kmp-default~20070720_2.6.22.18_0.2~2.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"adm8211-kmp-xen", rpm:"adm8211-kmp-xen~20070720_2.6.22.18_0.2~2.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"adm8211-kmp-xenpae", rpm:"adm8211-kmp-xenpae~20070720_2.6.22.18_0.2~2.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"alsa", rpm:"alsa~1.0.14~31.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"alsa-devel", rpm:"alsa-devel~1.0.14~31.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"alsa-docs", rpm:"alsa-docs~1.0.14~31.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"amarok", rpm:"amarok~1.4.7~37.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"amarok-lang", rpm:"amarok-lang~1.4.7~37.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"amarok-libvisual", rpm:"amarok-libvisual~1.4.7~37.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"amarok-xine", rpm:"amarok-xine~1.4.7~37.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"amarok-yauap", rpm:"amarok-yauap~1.4.7~37.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ant-phone", rpm:"ant-phone~2007.10.9~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.2.4~70.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-devel", rpm:"apache2-devel~2.2.4~70.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.2.4~70.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.2.4~70.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_jk", rpm:"apache2-mod_jk~1.2.21~59.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.2.4~70.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.2.4~70.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.2.4~70.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"appleir-kmp-bigsmp", rpm:"appleir-kmp-bigsmp~1.1_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"appleir-kmp-debug", rpm:"appleir-kmp-debug~1.1_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"appleir-kmp-default", rpm:"appleir-kmp-default~1.1_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"appleir-kmp-xen", rpm:"appleir-kmp-xen~1.1_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"appleir-kmp-xenpae", rpm:"appleir-kmp-xenpae~1.1_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"at76_usb-kmp-bigsmp", rpm:"at76_usb-kmp-bigsmp~0.14beta1_2.6.22.18_0.2~4.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"at76_usb-kmp-debug", rpm:"at76_usb-kmp-debug~0.14beta1_2.6.22.18_0.2~4.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"at76_usb-kmp-default", rpm:"at76_usb-kmp-default~0.14beta1_2.6.22.18_0.2~4.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"at76_usb-kmp-xen", rpm:"at76_usb-kmp-xen~0.14beta1_2.6.22.18_0.2~4.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"at76_usb-kmp-xenpae", rpm:"at76_usb-kmp-xenpae~0.14beta1_2.6.22.18_0.2~4.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"audit", rpm:"audit~1.5.5~13.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"audit-devel", rpm:"audit-devel~1.5.5~13.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"audit-libs", rpm:"audit-libs~1.5.5~13.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"audit-libs-python", rpm:"audit-libs-python~1.5.5~20.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"aufs-kmp-bigsmp", rpm:"aufs-kmp-bigsmp~cvs20070604_2.6.22.18_0.2~44.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"aufs-kmp-debug", rpm:"aufs-kmp-debug~cvs20070604_2.6.22.18_0.2~44.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"aufs-kmp-default", rpm:"aufs-kmp-default~cvs20070604_2.6.22.18_0.2~44.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"aufs-kmp-xen", rpm:"aufs-kmp-xen~cvs20070604_2.6.22.18_0.2~44.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"aufs-kmp-xenpae", rpm:"aufs-kmp-xenpae~cvs20070604_2.6.22.18_0.2~44.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"autofs", rpm:"autofs~5.0.2~30.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.4.1.P1~12.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.4.1.P1~12.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.4.1.P1~12.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.4.1.P1~12.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.4.1.P1~12.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.4.1.P1~12.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bluez-cups", rpm:"bluez-cups~3.18~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bluez-libs", rpm:"bluez-libs~3.18~5.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bluez-test", rpm:"bluez-test~3.18~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bluez-utils", rpm:"bluez-utils~3.18~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"boost", rpm:"boost~1.33.1~108.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"boost-devel", rpm:"boost-devel~1.33.1~108.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"boost-doc", rpm:"boost-doc~1.33.1~108.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bug-buddy", rpm:"bug-buddy~2.20.1~1.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bug-buddy-lang", rpm:"bug-buddy-lang~2.20.1~1.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bytefx-data-mysql", rpm:"bytefx-data-mysql~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bzip2", rpm:"bzip2~1.0.4~42.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bzip2-doc", rpm:"bzip2-doc~1.0.4~42.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cairo", rpm:"cairo~1.4.10~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cairo-devel", rpm:"cairo-devel~1.4.10~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cairo-doc", rpm:"cairo-doc~1.4.10~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"capi4linux", rpm:"capi4linux~2007.10.9~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"capi4linux-devel", rpm:"capi4linux-devel~2007.10.9~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cifs-mount", rpm:"cifs-mount~3.0.26a~3.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.94.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.94.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"claws-mail", rpm:"claws-mail~2.10.0~35.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"claws-mail-devel", rpm:"claws-mail-devel~2.10.0~35.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cloop-kmp-bigsmp", rpm:"cloop-kmp-bigsmp~2.04_2.6.22.18_0.2~118.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cloop-kmp-debug", rpm:"cloop-kmp-debug~2.04_2.6.22.18_0.2~118.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cloop-kmp-default", rpm:"cloop-kmp-default~2.04_2.6.22.18_0.2~118.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cloop-kmp-xen", rpm:"cloop-kmp-xen~2.04_2.6.22.18_0.2~118.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cloop-kmp-xenpae", rpm:"cloop-kmp-xenpae~2.04_2.6.22.18_0.2~118.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g", rpm:"compat-openssl097g~0.9.7g~75.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"control-center2", rpm:"control-center2~2.20.0~7.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"control-center2-devel", rpm:"control-center2-devel~2.20.0~7.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"courier-authlib", rpm:"courier-authlib~0.59.3~44.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"courier-authlib-devel", rpm:"courier-authlib-devel~0.59.3~44.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"courier-authlib-ldap", rpm:"courier-authlib-ldap~0.59.3~44.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"courier-authlib-mysql", rpm:"courier-authlib-mysql~0.59.3~44.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"courier-authlib-pgsql", rpm:"courier-authlib-pgsql~0.59.3~44.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"courier-authlib-pipe", rpm:"courier-authlib-pipe~0.59.3~44.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"courier-authlib-userdb", rpm:"courier-authlib-userdb~0.59.3~44.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cpio", rpm:"cpio~2.9~17.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.2.12~22.19", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-autoconfig", rpm:"cups-autoconfig~0.1.0~27.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~1.2.12~22.19", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.2.12~22.19", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.2.12~22.19", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dazuko-kmp-bigsmp", rpm:"dazuko-kmp-bigsmp~2.3.3.4_2.6.22.18_0.2~56.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dazuko-kmp-debug", rpm:"dazuko-kmp-debug~2.3.3.4_2.6.22.18_0.2~56.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dazuko-kmp-default", rpm:"dazuko-kmp-default~2.3.3.4_2.6.22.18_0.2~56.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dazuko-kmp-xen", rpm:"dazuko-kmp-xen~2.3.3.4_2.6.22.18_0.2~56.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dazuko-kmp-xenpae", rpm:"dazuko-kmp-xenpae~2.3.3.4_2.6.22.18_0.2~56.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1", rpm:"dbus-1~1.0.2~59.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-devel", rpm:"dbus-1-devel~1.0.2~59.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-devel-doc", rpm:"dbus-1-devel-doc~1.0.2~59.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib", rpm:"dbus-1-glib~0.74~25.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-devel", rpm:"dbus-1-glib-devel~0.74~25.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-doc", rpm:"dbus-1-glib-doc~0.74~25.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-mono", rpm:"dbus-1-mono~0.63~90.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-python", rpm:"dbus-1-python~0.82.0~28.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3", rpm:"dbus-1-qt3~0.62~110.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-devel", rpm:"dbus-1-qt3-devel~0.62~110.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-x11", rpm:"dbus-1-x11~1.0.2~67.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"deskbar-applet", rpm:"deskbar-applet~2.20.0~7.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"deskbar-applet-devel", rpm:"deskbar-applet-devel~2.20.0~7.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcpcd", rpm:"dhcpcd~1.3.22pl4~287.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dicts", rpm:"dicts~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"digikam", rpm:"digikam~0.9.2~51.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"digikamimageplugins", rpm:"digikamimageplugins~0.9.2~51.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"digikamimageplugins-superimpose", rpm:"digikamimageplugins-superimpose~0.9.2~51.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dmapi", rpm:"dmapi~2.2.8~22.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dmapi-devel", rpm:"dmapi-devel~2.2.8~22.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.45~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~1.0.5~6.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dovecot-devel", rpm:"dovecot-devel~1.0.5~6.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"drbd-kmp-bigsmp", rpm:"drbd-kmp-bigsmp~8.0.6_2.6.22.18_0.2~8.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"drbd-kmp-debug", rpm:"drbd-kmp-debug~8.0.6_2.6.22.18_0.2~8.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"drbd-kmp-default", rpm:"drbd-kmp-default~8.0.6_2.6.22.18_0.2~8.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"drbd-kmp-xen", rpm:"drbd-kmp-xen~8.0.6_2.6.22.18_0.2~8.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"drbd-kmp-xenpae", rpm:"drbd-kmp-xenpae~8.0.6_2.6.22.18_0.2~8.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"e2fsprogs", rpm:"e2fsprogs~1.40.2~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"e2fsprogs-devel", rpm:"e2fsprogs-devel~1.40.2~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"eclipse-archdep-platform", rpm:"eclipse-archdep-platform~3.3~45.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"eclipse-archdep-platform-commons", rpm:"eclipse-archdep-platform-commons~3.3~45.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"emacs", rpm:"emacs~22.1~40.12", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"emacs-el", rpm:"emacs-el~22.1~40.12", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"emacs-info", rpm:"emacs-info~22.1~40.12", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"emacs-nox", rpm:"emacs-nox~22.1~40.12", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"emacs-x11", rpm:"emacs-x11~22.1~40.12", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"enscript", rpm:"enscript~1.6.4~83.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany", rpm:"epiphany~2.20.0~8.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany-devel", rpm:"epiphany-devel~2.20.0~8.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany-doc", rpm:"epiphany-doc~2.20.0~8.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany-extensions", rpm:"epiphany-extensions~2.20.0~8.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany-extensions-lang", rpm:"epiphany-extensions-lang~2.20.0~8.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany-lang", rpm:"epiphany-lang~2.20.0~8.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evince", rpm:"evince~2.20.0~5.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evince-doc", rpm:"evince-doc~2.20.0~5.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evince-lang", rpm:"evince-lang~2.20.0~5.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.12.0~5.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~1.12.0~5.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server-devel", rpm:"evolution-data-server-devel~1.12.0~5.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server-doc", rpm:"evolution-data-server-doc~1.12.0~5.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.12.0~5.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.12.0~5.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"f-spot", rpm:"f-spot~0.4.0~35.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"f-spot-lang", rpm:"f-spot-lang~0.4.0~35.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fetchmail", rpm:"fetchmail~6.3.8~57.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fetchmailconf", rpm:"fetchmailconf~6.3.8~57.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fileshareset", rpm:"fileshareset~2.0~372.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.3.1~26.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.3.1~26.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"flac", rpm:"flac~1.2.0~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"flac-devel", rpm:"flac-devel~1.2.0~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~9.0.152.0~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"freeradius", rpm:"freeradius~1.1.6~47.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"freeradius-devel", rpm:"freeradius-devel~1.1.6~47.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"freeradius-dialupadmin", rpm:"freeradius-dialupadmin~1.1.6~47.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.3.5~18.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.3.5~18.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fvwm2", rpm:"fvwm2~2.5.23~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fvwm2-gtk", rpm:"fvwm2-gtk~2.5.23~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gdm", rpm:"gdm~2.20.0~8.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gettext", rpm:"gettext~0.16~47.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gettext-devel", rpm:"gettext-devel~0.16~47.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ggreeter", rpm:"ggreeter~0.1~30.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-fonts-other", rpm:"ghostscript-fonts-other~8.15.4~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-fonts-rus", rpm:"ghostscript-fonts-rus~8.15.4~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-fonts-std", rpm:"ghostscript-fonts-std~8.15.4~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-ijs-devel", rpm:"ghostscript-ijs-devel~8.15.4~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-library", rpm:"ghostscript-library~8.15.4~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-omni", rpm:"ghostscript-omni~8.15.4~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-x11", rpm:"ghostscript-x11~8.15.4~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"git", rpm:"git~1.5.2.4~24.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"git-arch", rpm:"git-arch~1.5.2.4~24.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"git-core", rpm:"git-core~1.5.2.4~24.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"git-cvs", rpm:"git-cvs~1.5.2.4~24.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"git-email", rpm:"git-email~1.5.2.4~24.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"git-svn", rpm:"git-svn~1.5.2.4~24.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gitk", rpm:"gitk~1.5.2.4~24.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib2", rpm:"glib2~2.14.1~4.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib2-devel", rpm:"glib2-devel~2.14.1~4.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib2-doc", rpm:"glib2-doc~2.14.1~4.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.6.1~18.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.6.1~18.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.6.1~18.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.6.1~18.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.6.1~18.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.6.1~18.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glibc-obsolete", rpm:"glibc-obsolete~2.6.1~18.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.6.1~18.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gmime", rpm:"gmime~2.2.10~35.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gmime-devel", rpm:"gmime-devel~2.2.10~35.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gmime-doc", rpm:"gmime-doc~2.2.10~35.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gmime-sharp", rpm:"gmime-sharp~2.2.10~35.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-cups-manager", rpm:"gnome-cups-manager~0.32cvs20060120~169.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-cups-manager-devel", rpm:"gnome-cups-manager-devel~0.32cvs20060120~169.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-cups-manager-lang", rpm:"gnome-cups-manager-lang~0.32cvs20060120~169.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-main-menu", rpm:"gnome-main-menu~0.9.8~94.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-main-menu-devel", rpm:"gnome-main-menu-devel~0.9.8~94.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-main-menu-lang", rpm:"gnome-main-menu-lang~0.9.8~94.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-mount", rpm:"gnome-mount~0.6~30.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-mount-lang", rpm:"gnome-mount-lang~0.6~30.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-power-manager", rpm:"gnome-power-manager~2.20.0~6.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-power-manager-lang", rpm:"gnome-power-manager-lang~2.20.0~6.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-screensaver", rpm:"gnome-screensaver~2.20.0~6.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-session", rpm:"gnome-session~2.20.0~8.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-volume-manager", rpm:"gnome-volume-manager~2.17.0~105.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-volume-manager-lang", rpm:"gnome-volume-manager-lang~2.17.0~105.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnumeric", rpm:"gnumeric~1.7.11~32.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnumeric-devel", rpm:"gnumeric-devel~1.7.11~32.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~1.6.1~36.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnutls-devel", rpm:"gnutls-devel~1.6.1~36.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-devel", rpm:"graphviz-devel~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-doc", rpm:"graphviz-doc~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-gd", rpm:"graphviz-gd~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-guile", rpm:"graphviz-guile~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-java", rpm:"graphviz-java~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-lua", rpm:"graphviz-lua~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-ocaml", rpm:"graphviz-ocaml~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-perl", rpm:"graphviz-perl~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-php", rpm:"graphviz-php~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-python", rpm:"graphviz-python~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-ruby", rpm:"graphviz-ruby~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-sharp", rpm:"graphviz-sharp~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-tcl", rpm:"graphviz-tcl~2.12~50.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gspcav-kmp-bigsmp", rpm:"gspcav-kmp-bigsmp~01.00.12_2.6.22.18_0.2~6.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gspcav-kmp-debug", rpm:"gspcav-kmp-debug~01.00.12_2.6.22.18_0.2~6.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gspcav-kmp-default", rpm:"gspcav-kmp-default~01.00.12_2.6.22.18_0.2~6.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gspcav-kmp-xen", rpm:"gspcav-kmp-xen~01.00.12_2.6.22.18_0.2~6.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gspcav-kmp-xenpae", rpm:"gspcav-kmp-xenpae~01.00.12_2.6.22.18_0.2~6.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer010-plugins-good", rpm:"gstreamer010-plugins-good~0.10.6~41.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer010-plugins-good-doc", rpm:"gstreamer010-plugins-good-doc~0.10.6~41.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer010-plugins-good-extra", rpm:"gstreamer010-plugins-good-extra~0.10.6~41.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gtk2", rpm:"gtk2~2.12.0~5.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gtk2-devel", rpm:"gtk2-devel~2.12.0~5.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gtk2-doc", rpm:"gtk2-doc~2.12.0~5.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gvim", rpm:"gvim~7.1~44.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal", rpm:"hal~0.5.9_git20070831~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-devel", rpm:"hal-devel~0.5.9_git20070831~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-doc", rpm:"hal-doc~0.5.9_git20070831~15.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hplip", rpm:"hplip~2.7.7~37.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hplip-hpijs", rpm:"hplip-hpijs~2.7.7~37.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"htdig", rpm:"htdig~3.2.0b6~110.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"htdig-devel", rpm:"htdig-devel~3.2.0b6~110.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"htdig-doc", rpm:"htdig-doc~3.2.0b6~110.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"htop", rpm:"htop~0.6.6~24.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hugin", rpm:"hugin~0.6.99.4~33.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"i4l-base", rpm:"i4l-base~2007.10.9~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"i4l-isdnlog", rpm:"i4l-isdnlog~2007.10.9~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"i4l-vbox", rpm:"i4l-vbox~2007.10.9~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"i4lfirm", rpm:"i4lfirm~2007.10.9~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ib-bonding-kmp-bigsmp", rpm:"ib-bonding-kmp-bigsmp~0.9.0_2.6.22.18_0.2~29.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ib-bonding-kmp-debug", rpm:"ib-bonding-kmp-debug~0.9.0_2.6.22.18_0.2~29.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ib-bonding-kmp-default", rpm:"ib-bonding-kmp-default~0.9.0_2.6.22.18_0.2~29.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ibm-data-db2", rpm:"ibm-data-db2~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"icu", rpm:"icu~3.6~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"icu-data", rpm:"icu-data~3.6~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imap", rpm:"imap~2006c1_suse~51.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imap-devel", rpm:"imap-devel~2006c1_suse~51.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imap-lib", rpm:"imap-lib~2006c1_suse~51.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imlib2", rpm:"imlib2~1.3.0~66.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imlib2-devel", rpm:"imlib2-devel~1.3.0~66.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imlib2-filters", rpm:"imlib2-filters~1.3.0~66.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imlib2-loaders", rpm:"imlib2-loaders~1.3.0~66.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ipsec-tools", rpm:"ipsec-tools~0.6.5~104.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ipw3945-kmp-bigsmp", rpm:"ipw3945-kmp-bigsmp~1.2.2_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ipw3945-kmp-debug", rpm:"ipw3945-kmp-debug~1.2.2_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ipw3945-kmp-default", rpm:"ipw3945-kmp-default~1.2.2_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ipw3945-kmp-xen", rpm:"ipw3945-kmp-xen~1.2.2_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ipw3945-kmp-xenpae", rpm:"ipw3945-kmp-xenpae~1.2.2_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ipw3945d", rpm:"ipw3945d~1.7.22~8.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-brazilian", rpm:"ispell-brazilian~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-catalan", rpm:"ispell-catalan~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-czech", rpm:"ispell-czech~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-danish", rpm:"ispell-danish~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-dutch", rpm:"ispell-dutch~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-esperanto", rpm:"ispell-esperanto~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-estonian", rpm:"ispell-estonian~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-finnish", rpm:"ispell-finnish~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-french", rpm:"ispell-french~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-german", rpm:"ispell-german~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-greek", rpm:"ispell-greek~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-italian", rpm:"ispell-italian~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-ngerman", rpm:"ispell-ngerman~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-norsk", rpm:"ispell-norsk~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-nswiss", rpm:"ispell-nswiss~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-polish", rpm:"ispell-polish~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-portuguese", rpm:"ispell-portuguese~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-russian", rpm:"ispell-russian~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-slovene", rpm:"ispell-slovene~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-spanish", rpm:"ispell-spanish~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ispell-swedish", rpm:"ispell-swedish~1.5~322.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ivtv-kmp-bigsmp", rpm:"ivtv-kmp-bigsmp~0.10.3_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ivtv-kmp-debug", rpm:"ivtv-kmp-debug~0.10.3_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ivtv-kmp-default", rpm:"ivtv-kmp-default~0.10.3_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ivtv-kmp-xen", rpm:"ivtv-kmp-xen~0.10.3_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ivtv-kmp-xenpae", rpm:"ivtv-kmp-xenpae~0.10.3_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iwlwifi-kmp-bigsmp", rpm:"iwlwifi-kmp-bigsmp~1.2.0_2.6.22.18_0.2~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iwlwifi-kmp-debug", rpm:"iwlwifi-kmp-debug~1.2.0_2.6.22.18_0.2~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iwlwifi-kmp-default", rpm:"iwlwifi-kmp-default~1.2.0_2.6.22.18_0.2~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iwlwifi-kmp-xen", rpm:"iwlwifi-kmp-xen~1.2.0_2.6.22.18_0.2~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iwlwifi-kmp-xenpae", rpm:"iwlwifi-kmp-xenpae~1.2.0_2.6.22.18_0.2~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"jasper", rpm:"jasper~1.900.1~44.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun", rpm:"java-1_5_0-sun~1.5.0_update17~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-alsa", rpm:"java-1_5_0-sun-alsa~1.5.0_update17~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-demo", rpm:"java-1_5_0-sun-demo~1.5.0_update17~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-devel", rpm:"java-1_5_0-sun-devel~1.5.0_update17~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-jdbc", rpm:"java-1_5_0-sun-jdbc~1.5.0_update17~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-plugin", rpm:"java-1_5_0-sun-plugin~1.5.0_update17~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-src", rpm:"java-1_5_0-sun-src~1.5.0_update17~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun", rpm:"java-1_6_0-sun~1.6.0.u11~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-alsa", rpm:"java-1_6_0-sun-alsa~1.6.0.u11~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-debuginfo", rpm:"java-1_6_0-sun-debuginfo~1.6.0.u11~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-demo", rpm:"java-1_6_0-sun-demo~1.6.0.u11~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-devel", rpm:"java-1_6_0-sun-devel~1.6.0.u11~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-jdbc", rpm:"java-1_6_0-sun-jdbc~1.6.0.u11~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_6_0-sun-plugin", rpm:"java-1_6_0-sun-plugin~1.6.0.u11~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"jfbterm", rpm:"jfbterm~0.3.10~593.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"jhead", rpm:"jhead~2.7~11.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"jpackage-utils", rpm:"jpackage-utils~1.7.0~77.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase3", rpm:"kdebase3~3.5.7~87.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase3-SuSE", rpm:"kdebase3-SuSE~10.3~152.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase3-beagle", rpm:"kdebase3-beagle~3.5.7~87.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase3-devel", rpm:"kdebase3-devel~3.5.7~87.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase3-extra", rpm:"kdebase3-extra~3.5.7~87.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase3-kdm", rpm:"kdebase3-kdm~3.5.7~87.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase3-ksysguardd", rpm:"kdebase3-ksysguardd~3.5.7~87.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase3-nsplugin", rpm:"kdebase3-nsplugin~3.5.7~87.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase3-samba", rpm:"kdebase3-samba~3.5.7~87.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase3-session", rpm:"kdebase3-session~3.5.7~87.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics3", rpm:"kdegraphics3~3.5.7~60.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics3-3D", rpm:"kdegraphics3-3D~3.5.7~60.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics3-devel", rpm:"kdegraphics3-devel~3.5.7~60.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics3-extra", rpm:"kdegraphics3-extra~3.5.7~60.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics3-fax", rpm:"kdegraphics3-fax~3.5.7~60.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics3-imaging", rpm:"kdegraphics3-imaging~3.5.7~60.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics3-kamera", rpm:"kdegraphics3-kamera~3.5.7~60.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics3-pdf", rpm:"kdegraphics3-pdf~3.5.7~60.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics3-postscript", rpm:"kdegraphics3-postscript~3.5.7~60.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics3-scan", rpm:"kdegraphics3-scan~3.5.7~60.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics3-tex", rpm:"kdegraphics3-tex~3.5.7~60.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs3", rpm:"kdelibs3~3.5.7~72.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs3-arts", rpm:"kdelibs3-arts~3.5.7~72.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs3-default-style", rpm:"kdelibs3-default-style~3.5.7~72.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs3-devel", rpm:"kdelibs3-devel~3.5.7~72.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs3-doc", rpm:"kdelibs3-doc~3.5.7~72.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs4", rpm:"kdelibs4~3.93.0.svn712047~6.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs4-core", rpm:"kdelibs4-core~3.93.0.svn712047~6.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs4-doc", rpm:"kdelibs4-doc~3.93.0.svn712047~6.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdenetwork3-InstantMessenger", rpm:"kdenetwork3-InstantMessenger~3.5.7~64.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdewebdev3", rpm:"kdewebdev3~3.5.7~61.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~2.6.22.17~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~2.6.22.17~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.22.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kio_sysinfo", rpm:"kio_sysinfo~10.3~152.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"klamav", rpm:"klamav~0.41.1~32.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice", rpm:"koffice~1.6.3~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-database", rpm:"koffice-database~1.6.3~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-database-mysql", rpm:"koffice-database-mysql~1.6.3~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-database-psql", rpm:"koffice-database-psql~1.6.3~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-devel", rpm:"koffice-devel~1.6.3~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-extra", rpm:"koffice-extra~1.6.3~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-illustration", rpm:"koffice-illustration~1.6.3~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-planning", rpm:"koffice-planning~1.6.3~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-presentation", rpm:"koffice-presentation~1.6.3~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-python", rpm:"koffice-python~1.6.3~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-ruby", rpm:"koffice-ruby~1.6.3~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-spreadsheet", rpm:"koffice-spreadsheet~1.6.3~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"koffice-wordprocessing", rpm:"koffice-wordprocessing~1.6.3~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kommander", rpm:"kommander~3.5.7~61.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kommander-runtime", rpm:"kommander-runtime~3.5.7~61.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kmp-bigsmp", rpm:"kqemu-kmp-bigsmp~1.3.0pre11_2.6.22.18_0.2~7.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kmp-debug", rpm:"kqemu-kmp-debug~1.3.0pre11_2.6.22.18_0.2~7.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kmp-default", rpm:"kqemu-kmp-default~1.3.0pre11_2.6.22.18_0.2~7.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kmp-xen", rpm:"kqemu-kmp-xen~1.3.0pre11_2.6.22.18_0.2~7.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kmp-xenpae", rpm:"kqemu-kmp-xenpae~1.3.0pre11_2.6.22.18_0.2~7.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.2~22.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.6.2~22.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.6.2~22.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.6.2~22.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.2~22.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.2~22.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ksh", rpm:"ksh~93s~48.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ksh-devel", rpm:"ksh-devel~93s~48.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ktorrent", rpm:"ktorrent~2.2.1~32.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kvm-kmp-bigsmp", rpm:"kvm-kmp-bigsmp~36_2.6.22.18_0.2~13.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kvm-kmp-default", rpm:"kvm-kmp-default~36_2.6.22.18_0.2~13.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kwin-decor-suse2", rpm:"kwin-decor-suse2~0.4.1~32.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ldapsmb", rpm:"ldapsmb~1.34b~110.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"less", rpm:"less~406~16.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libFLAC++6", rpm:"libFLAC++6~1.2.0~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libFLAC8", rpm:"libFLAC8~1.2.0~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagick++-devel", rpm:"libGraphicsMagick++-devel~1.1.8~20.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagick++1", rpm:"libGraphicsMagick++1~1.1.8~20.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagick1", rpm:"libGraphicsMagick1~1.1.8~20.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagickWand0", rpm:"libGraphicsMagickWand0~1.1.8~20.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~6.3.5.10~2.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick++10", rpm:"libMagick++10~6.3.5.10~2.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick10", rpm:"libMagick10~6.3.5.10~2.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libWand10", rpm:"libWand10~6.3.5.10~2.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libaio-devel", rpm:"libaio-devel~0.3.104~74.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libasound2", rpm:"libasound2~1.0.14~31.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libblkid-devel", rpm:"libblkid-devel~1.40.2~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libblkid1", rpm:"libblkid1~1.40.2~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libbonobo", rpm:"libbonobo~2.20.0~5.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libbonobo-devel", rpm:"libbonobo-devel~2.20.0~5.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libbonobo-doc", rpm:"libbonobo-doc~2.20.0~5.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libbz2-1", rpm:"libbz2-1~1.0.4~42.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libbz2-devel", rpm:"libbz2-devel~1.0.4~42.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcdaudio", rpm:"libcdaudio~0.99.12~75.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcdaudio-devel", rpm:"libcdaudio-devel~0.99.12~75.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcdio++0", rpm:"libcdio++0~0.78.2~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcdio-devel", rpm:"libcdio-devel~0.78.2~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcdio-utils", rpm:"libcdio-utils~0.78.2~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcdio7", rpm:"libcdio7~0.78.2~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcdio_cdda0", rpm:"libcdio_cdda0~0.78.2~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcdio_paranoia0", rpm:"libcdio_paranoia0~0.78.2~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcom_err-devel", rpm:"libcom_err-devel~1.40.2~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcom_err2", rpm:"libcom_err2~1.40.2~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.16.4~16.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libdigikam-devel", rpm:"libdigikam-devel~0.9.2~51.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libexif", rpm:"libexif~0.6.16~23.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libexif-devel", rpm:"libexif-devel~0.6.16~23.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libexif5", rpm:"libexif5~0.5.12~80.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libexiv2", rpm:"libexiv2~0.15~8.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.15~8.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libext2fs-devel", rpm:"libext2fs-devel~1.40.2~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libext2fs2", rpm:"libext2fs2~1.40.2~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgadu", rpm:"libgadu~1.7.1~29.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgadu-devel", rpm:"libgadu-devel~1.7.1~29.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgimpprint", rpm:"libgimpprint~4.2.7~178.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgimpprint-devel", rpm:"libgimpprint-devel~4.2.7~178.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgmime-2_0-2", rpm:"libgmime-2_0-2~2.2.10~35.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnomecanvas", rpm:"libgnomecanvas~2.20.0~4.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnomecanvas-devel", rpm:"libgnomecanvas-devel~2.20.0~4.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnomecanvas-doc", rpm:"libgnomecanvas-doc~2.20.0~4.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnomecups", rpm:"libgnomecups~0.2.2~123.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnomecups-devel", rpm:"libgnomecups-devel~0.2.2~123.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnomesu", rpm:"libgnomesu~1.0.0~153.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnomesu-devel", rpm:"libgnomesu-devel~1.0.0~153.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnomesu-lang", rpm:"libgnomesu-lang~1.0.0~153.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnomeui", rpm:"libgnomeui~2.20.0~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnomeui-devel", rpm:"libgnomeui-devel~2.20.0~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnomeui-doc", rpm:"libgnomeui-doc~2.20.0~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgphoto2", rpm:"libgphoto2~2.4.0~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgphoto2-devel", rpm:"libgphoto2-devel~2.4.0~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libicu", rpm:"libicu~3.6~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libicu-devel", rpm:"libicu-devel~3.6~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libicu-doc", rpm:"libicu-doc~3.6~13.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libiso9660-5", rpm:"libiso9660-5~0.78.2~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libjasper", rpm:"libjasper~1.900.1~44.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libjasper-devel", rpm:"libjasper-devel~1.900.1~44.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkde4", rpm:"libkde4~3.93.0.svn712047~6.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkde4-devel", rpm:"libkde4-devel~3.93.0.svn712047~6.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdecore4", rpm:"libkdecore4~3.93.0.svn712047~6.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdecore4-devel", rpm:"libkdecore4-devel~3.93.0.svn712047~6.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"liblcms", rpm:"liblcms~1.16~39.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"liblcms-devel", rpm:"liblcms-devel~1.16~39.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmsrpc", rpm:"libmsrpc~3.0.26a~3.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmsrpc-devel", rpm:"libmsrpc-devel~3.0.26a~3.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmysqlclient-devel", rpm:"libmysqlclient-devel~5.0.45~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmysqlclient15", rpm:"libmysqlclient15~5.0.45~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmysqlclient_r15", rpm:"libmysqlclient_r15~5.0.45~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnetpbm-devel", rpm:"libnetpbm-devel~10.26.44~10.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnetpbm10", rpm:"libnetpbm10~10.26.44~10.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopensc2", rpm:"libopensc2~0.11.3~21.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8e~45.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8e~45.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.2.18~15.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.18~15.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.3.1~26.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.3.1~26.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-meanwhile", rpm:"libpurple-meanwhile~2.3.1~26.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-mono", rpm:"libpurple-mono~2.3.1~26.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt4", rpm:"libqt4~4.3.1~23.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt4-dbus-1", rpm:"libqt4-dbus-1~4.3.1~23.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt4-devel", rpm:"libqt4-devel~4.3.1~23.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt4-devel-doc", rpm:"libqt4-devel-doc~4.3.1~23.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt4-qt3support", rpm:"libqt4-qt3support~4.3.1~23.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt4-sql", rpm:"libqt4-sql~4.3.1~23.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt4-sql-mysql", rpm:"libqt4-sql-mysql~4.3.1~7.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt4-sql-sqlite", rpm:"libqt4-sql-sqlite~4.3.1~7.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt4-sql-unixODBC", rpm:"libqt4-sql-unixODBC~4.3.1~7.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libqt4-x11", rpm:"libqt4-x11~4.3.1~23.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"librpcsecgss", rpm:"librpcsecgss~0.14~71.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.0.26a~3.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~3.0.26a~3.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbsharemodes", rpm:"libsmbsharemodes~3.0.26a~3.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbsharemodes-devel", rpm:"libsmbsharemodes-devel~3.0.26a~3.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsnmp15", rpm:"libsnmp15~5.4.1~19.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.2.100~45.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsoup-devel", rpm:"libsoup-devel~2.2.100~45.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsoup-doc", rpm:"libsoup-doc~2.2.100~45.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~3.8.2~68.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtiff3", rpm:"libtiff3~3.8.2~68.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libudf0", rpm:"libudf0~0.78.2~3.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libuuid-devel", rpm:"libuuid-devel~1.40.2~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libuuid1", rpm:"libuuid1~1.40.2~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.3.0~30.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.3.0~30.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvirt-doc", rpm:"libvirt-doc~0.3.0~30.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.3.0~30.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvorbis", rpm:"libvorbis~1.2.0~11.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvorbis-devel", rpm:"libvorbis-devel~1.2.0~11.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvorbis-doc", rpm:"libvorbis-doc~1.2.0~11.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxfcegui4", rpm:"libxfcegui4~4.4.1~55.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxfcegui4-devel", rpm:"libxfcegui4-devel~4.4.1~55.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.6.30~4.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.6.30~4.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.6.30~4.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxslt", rpm:"libxslt~1.1.20~41.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.20~41.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~3.27.3~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libzypp-devel", rpm:"libzypp-devel~3.27.3~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"licq", rpm:"licq~1.3.4~125.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"licq-icqnd", rpm:"licq-icqnd~1.3.4~125.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lighttpd", rpm:"lighttpd~1.4.18~1.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lighttpd-mod_cml", rpm:"lighttpd-mod_cml~1.4.18~1.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lighttpd-mod_magnet", rpm:"lighttpd-mod_magnet~1.4.18~1.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lighttpd-mod_mysql_vhost", rpm:"lighttpd-mod_mysql_vhost~1.4.18~1.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lighttpd-mod_rrdtool", rpm:"lighttpd-mod_rrdtool~1.4.18~1.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lighttpd-mod_trigger_b4_dl", rpm:"lighttpd-mod_trigger_b4_dl~1.4.18~1.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lighttpd-mod_webdav", rpm:"lighttpd-mod_webdav~1.4.18~1.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lirc-kmp-bigsmp", rpm:"lirc-kmp-bigsmp~0.8.2_2.6.22.18_0.2~6.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lirc-kmp-default", rpm:"lirc-kmp-default~0.8.2_2.6.22.18_0.2~6.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lirc-kmp-xen", rpm:"lirc-kmp-xen~0.8.2_2.6.22.18_0.2~6.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lirc-kmp-xenpae", rpm:"lirc-kmp-xenpae~0.8.2_2.6.22.18_0.2~6.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lomoco", rpm:"lomoco~1.0~15.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lynx", rpm:"lynx~2.8.6~48.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mailman", rpm:"mailman~2.1.9~90.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mdadm", rpm:"mdadm~2.6.2~16.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"metacity", rpm:"metacity~2.20.0~4.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"metacity-devel", rpm:"metacity-devel~2.20.0~4.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mkinitrd", rpm:"mkinitrd~2.1~36.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-complete", rpm:"mono-complete~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-core", rpm:"mono-core~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data", rpm:"mono-data~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-firebird", rpm:"mono-data-firebird~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-oracle", rpm:"mono-data-oracle~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-postgresql", rpm:"mono-data-postgresql~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-sqlite", rpm:"mono-data-sqlite~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-sybase", rpm:"mono-data-sybase~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-devel", rpm:"mono-devel~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-extras", rpm:"mono-extras~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-jscript", rpm:"mono-jscript~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-locale-extras", rpm:"mono-locale-extras~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-nunit", rpm:"mono-nunit~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-web", rpm:"mono-web~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-winforms", rpm:"mono-winforms~1.2.5~16.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner181", rpm:"mozilla-xulrunner181~1.8.1.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner181-devel", rpm:"mozilla-xulrunner181-devel~1.8.1.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner181-l10n", rpm:"mozilla-xulrunner181-l10n~1.8.1.19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mtr", rpm:"mtr~0.72~94.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mtr-gtk", rpm:"mtr-gtk~0.72~94.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.45~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-Max", rpm:"mysql-Max~5.0.45~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.45~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.0.45~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-debug", rpm:"mysql-debug~5.0.45~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-query-browser", rpm:"mysql-query-browser~5.0r12~56.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.0.45~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nagios", rpm:"nagios~2.9~48.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nagios-plugins", rpm:"nagios-plugins~1.4.9~19.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nagios-plugins-extras", rpm:"nagios-plugins-extras~1.4.9~19.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nagios-www", rpm:"nagios-www~2.9~48.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"namazu", rpm:"namazu~2.0.18~24.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"namazu-cgi", rpm:"namazu-cgi~2.0.18~24.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"namazu-devel", rpm:"namazu-devel~2.0.18~24.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nautilus", rpm:"nautilus~2.20.0~5.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nautilus-devel", rpm:"nautilus-devel~2.20.0~5.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nautilus-gnome-main-menu", rpm:"nautilus-gnome-main-menu~0.9.8~94.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ndiswrapper", rpm:"ndiswrapper~1.47~32.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ndiswrapper-kmp-bigsmp", rpm:"ndiswrapper-kmp-bigsmp~1.47_2.6.22.19_0.1~32.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ndiswrapper-kmp-default", rpm:"ndiswrapper-kmp-default~1.47_2.6.22.19_0.1~32.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ndiswrapper-kmp-xen", rpm:"ndiswrapper-kmp-xen~1.47_2.6.22.19_0.1~32.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ndiswrapper-kmp-xenpae", rpm:"ndiswrapper-kmp-xenpae~1.47_2.6.22.19_0.1~32.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.4.1~19.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.4.1~19.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.26.44~10.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nouveau-kmp-bigsmp", rpm:"nouveau-kmp-bigsmp~0.20070905_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nouveau-kmp-debug", rpm:"nouveau-kmp-debug~0.20070905_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nouveau-kmp-default", rpm:"nouveau-kmp-default~0.20070905_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nouveau-kmp-xen", rpm:"nouveau-kmp-xen~0.20070905_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nouveau-kmp-xenpae", rpm:"nouveau-kmp-xenpae~0.20070905_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novell-ipsec-tools", rpm:"novell-ipsec-tools~0.6.3~114.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novell-ipsec-tools-devel", rpm:"novell-ipsec-tools-devel~0.6.3~114.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novfs-kmp-bigsmp", rpm:"novfs-kmp-bigsmp~2.0.0_2.6.22.18_0.2~23.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novfs-kmp-debug", rpm:"novfs-kmp-debug~2.0.0_2.6.22.18_0.2~23.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novfs-kmp-default", rpm:"novfs-kmp-default~2.0.0_2.6.22.18_0.2~23.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novfs-kmp-xen", rpm:"novfs-kmp-xen~2.0.0_2.6.22.18_0.2~23.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novfs-kmp-xenpae", rpm:"novfs-kmp-xenpae~2.0.0_2.6.22.18_0.2~23.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.6.1~18.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspluginwrapper", rpm:"nspluginwrapper~0.9.91.4~58.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nut", rpm:"nut~2.2.0~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nut-devel", rpm:"nut-devel~2.2.0~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvram-wakeup", rpm:"nvram-wakeup~0.97~19.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ofed-kmp-bigsmp", rpm:"ofed-kmp-bigsmp~1.2.5_2.6.22.18_0.2~18.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ofed-kmp-debug", rpm:"ofed-kmp-debug~1.2.5_2.6.22.18_0.2~18.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ofed-kmp-default", rpm:"ofed-kmp-default~1.2.5_2.6.22.18_0.2~18.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"omnibook-kmp-bigsmp", rpm:"omnibook-kmp-bigsmp~20070530_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"omnibook-kmp-debug", rpm:"omnibook-kmp-debug~20070530_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"omnibook-kmp-default", rpm:"omnibook-kmp-default~20070530_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"omnibook-kmp-xen", rpm:"omnibook-kmp-xen~20070530_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"omnibook-kmp-xenpae", rpm:"omnibook-kmp-xenpae~20070530_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opal", rpm:"opal~2.2.8~60.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opal-devel", rpm:"opal-devel~2.2.8~60.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"open-iscsi", rpm:"open-iscsi~2.0.866~15.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openldap2", rpm:"openldap2~2.3.37~7.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openldap2-back-meta", rpm:"openldap2-back-meta~2.3.37~7.10", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openldap2-back-perl", rpm:"openldap2-back-perl~2.3.37~7.10", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openldap2-client", rpm:"openldap2-client~2.3.37~20.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openldap2-devel", rpm:"openldap2-devel~2.3.37~20.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openmotif22-libs", rpm:"openmotif22-libs~2.2.4~84.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.11.3~21.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opensc-devel", rpm:"opensc-devel~0.11.3~21.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~4.6p1~58.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~4.6p1~58.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~45.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-certs", rpm:"openssl-certs~0.9.8e~45.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8e~45.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opensuse-updater-gnome", rpm:"opensuse-updater-gnome~0.4.5~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openvpn", rpm:"openvpn~2.0.9~44.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openwsman", rpm:"openwsman~1.2.0~14.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openwsman-client", rpm:"openwsman-client~1.2.0~14.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openwsman-devel", rpm:"openwsman-devel~1.2.0~14.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openwsman-server", rpm:"openwsman-server~1.2.0~14.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opera", rpm:"opera~9.63~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"otrs", rpm:"otrs~2.1.7~39.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"p54-kmp-bigsmp", rpm:"p54-kmp-bigsmp~20070806_2.6.22.18_0.2~2.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"p54-kmp-debug", rpm:"p54-kmp-debug~20070806_2.6.22.18_0.2~2.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"p54-kmp-default", rpm:"p54-kmp-default~20070806_2.6.22.18_0.2~2.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"p54-kmp-xen", rpm:"p54-kmp-xen~20070806_2.6.22.18_0.2~2.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"p54-kmp-xenpae", rpm:"p54-kmp-xenpae~20070806_2.6.22.18_0.2~2.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pam-config", rpm:"pam-config~0.23~9.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pam_krb5", rpm:"pam_krb5~2.2.17~14.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pam_mount", rpm:"pam_mount~0.18~84.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pan", rpm:"pan~0.132~33.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcc-acpi-kmp-bigsmp", rpm:"pcc-acpi-kmp-bigsmp~0.9_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcc-acpi-kmp-debug", rpm:"pcc-acpi-kmp-debug~0.9_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcc-acpi-kmp-default", rpm:"pcc-acpi-kmp-default~0.9_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcc-acpi-kmp-xen", rpm:"pcc-acpi-kmp-xen~0.9_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcc-acpi-kmp-xenpae", rpm:"pcc-acpi-kmp-xenpae~0.9_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcfclock-kmp-bigsmp", rpm:"pcfclock-kmp-bigsmp~0.44_2.6.22.18_0.2~133.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcfclock-kmp-debug", rpm:"pcfclock-kmp-debug~0.44_2.6.22.18_0.2~133.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcfclock-kmp-default", rpm:"pcfclock-kmp-default~0.44_2.6.22.18_0.2~133.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcre", rpm:"pcre~7.2~14.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcre-devel", rpm:"pcre-devel~7.2~14.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pdns", rpm:"pdns~2.9.21~57.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pdns-backend-ldap", rpm:"pdns-backend-ldap~2.9.21~57.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pdns-backend-mysql", rpm:"pdns-backend-mysql~2.9.21~57.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pdns-backend-postgresql", rpm:"pdns-backend-postgresql~2.9.21~57.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pdns-backend-sqlite2", rpm:"pdns-backend-sqlite2~2.9.21~57.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pdns-backend-sqlite3", rpm:"pdns-backend-sqlite3~2.9.21~57.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pdns-recursor", rpm:"pdns-recursor~3.1.4~58.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl", rpm:"perl~5.8.8~76.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Bootloader", rpm:"perl-Bootloader~0.4.32.21~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-GraphicsMagick", rpm:"perl-GraphicsMagick~1.1.8~20.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~6.3.5.10~2.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.4.1~19.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Tk", rpm:"perl-Tk~804.027~95.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-base", rpm:"perl-base~5.8.8~76.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-spamassassin", rpm:"perl-spamassassin~3.2.3~10.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5", rpm:"php5~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-dbase", rpm:"php5-dbase~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-devel", rpm:"php5-devel~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-hash", rpm:"php5-hash~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-imap", rpm:"php5-imap~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-json", rpm:"php5-json~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-mhash", rpm:"php5-mhash~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-ncurses", rpm:"php5-ncurses~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-posix", rpm:"php5-posix~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-readline", rpm:"php5-readline~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-sockets", rpm:"php5-sockets~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-sqlite", rpm:"php5-sqlite~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-suhosin", rpm:"php5-suhosin~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-tidy", rpm:"php5-tidy~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-xmlwriter", rpm:"php5-xmlwriter~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-zip", rpm:"php5-zip~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.2.6~0.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.3.1~26.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.3.1~26.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pm-utils", rpm:"pm-utils~0.99.3.20070618~18.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.5.4~101.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-devel", rpm:"poppler-devel~0.5.4~101.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-doc", rpm:"poppler-doc~0.5.4~101.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-glib", rpm:"poppler-glib~0.5.4~101.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-qt", rpm:"poppler-qt~0.5.4~101.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-qt4", rpm:"poppler-qt4~0.5.4~101.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~0.5.4~101.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.4.5~20.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postfix-devel", rpm:"postfix-devel~2.4.5~20.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~2.4.5~20.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postfix-postgresql", rpm:"postfix-postgresql~2.4.5~20.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.2.6~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~8.2.6~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~8.2.6~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~8.2.6~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~8.2.6~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~8.2.6~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~8.2.6~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~8.2.6~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~8.2.6~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"procinfo", rpm:"procinfo~18~128.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python", rpm:"python~2.5.1~39.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-curses", rpm:"python-curses~2.5.1~39.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-demo", rpm:"python-demo~2.5.1~39.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.5.1~39.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-gdbm", rpm:"python-gdbm~2.5.1~39.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-idle", rpm:"python-idle~2.5.1~39.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-tk", rpm:"python-tk~2.5.1~39.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-xml", rpm:"python-xml~2.5.1~39.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~0.9.0.cvs~35.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt3", rpm:"qt3~3.3.8~76.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt3-devel", rpm:"qt3-devel~3.3.8~76.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"quickcam-kmp-bigsmp", rpm:"quickcam-kmp-bigsmp~0.6.6_2.6.22.18_0.2~5.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"quickcam-kmp-default", rpm:"quickcam-kmp-default~0.6.6_2.6.22.18_0.2~5.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rdesktop", rpm:"rdesktop~1.5.0~79.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rfswitch-kmp-bigsmp", rpm:"rfswitch-kmp-bigsmp~1.1_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rfswitch-kmp-debug", rpm:"rfswitch-kmp-debug~1.1_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rfswitch-kmp-default", rpm:"rfswitch-kmp-default~1.1_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rfswitch-kmp-xen", rpm:"rfswitch-kmp-xen~1.1_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rfswitch-kmp-xenpae", rpm:"rfswitch-kmp-xenpae~1.1_2.6.22.18_0.2~3.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rsh", rpm:"rsh~0.17~638.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rsh-server", rpm:"rsh-server~0.17~638.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rsync", rpm:"rsync~2.6.9~55.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rt2x00-kmp-bigsmp", rpm:"rt2x00-kmp-bigsmp~2.0.6+git20070816_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rt2x00-kmp-debug", rpm:"rt2x00-kmp-debug~2.0.6+git20070816_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rt2x00-kmp-default", rpm:"rt2x00-kmp-default~2.0.6+git20070816_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rt2x00-kmp-xen", rpm:"rt2x00-kmp-xen~2.0.6+git20070816_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rt2x00-kmp-xenpae", rpm:"rt2x00-kmp-xenpae~2.0.6+git20070816_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rtl8187-kmp-bigsmp", rpm:"rtl8187-kmp-bigsmp~20070806_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rtl8187-kmp-debug", rpm:"rtl8187-kmp-debug~20070806_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rtl8187-kmp-default", rpm:"rtl8187-kmp-default~20070806_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rtl8187-kmp-xen", rpm:"rtl8187-kmp-xen~20070806_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rtl8187-kmp-xenpae", rpm:"rtl8187-kmp-xenpae~20070806_2.6.22.18_0.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.6.p36~20.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.6.p36~20.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-doc-html", rpm:"ruby-doc-html~1.8.6.p36~20.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-doc-ri", rpm:"ruby-doc-ri~1.8.6.p36~20.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-examples", rpm:"ruby-examples~1.8.6.p36~20.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-test-suite", rpm:"ruby-test-suite~1.8.6.p36~20.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-tk", rpm:"ruby-tk~1.8.6.p36~20.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rubygem-actionpack", rpm:"rubygem-actionpack~1.13.3~20.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rubygem-activerecord", rpm:"rubygem-activerecord~1.15.3~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rubygem-activesupport", rpm:"rubygem-activesupport~1.4.2~20.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rxvt-unicode", rpm:"rxvt-unicode~8.3~16.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.0.26a~3.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.26a~3.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-devel", rpm:"samba-devel~3.0.26a~3.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-krb-printing", rpm:"samba-krb-printing~3.0.26a~3.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-python", rpm:"samba-python~3.0.26a~3.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-vscan", rpm:"samba-vscan~0.3.6b~181.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.0.26a~3.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"sarg", rpm:"sarg~2.2.3.1~39.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"scim-bridge", rpm:"scim-bridge~0.4.13~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"scim-bridge-gtk", rpm:"scim-bridge-gtk~0.4.13~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"scim-bridge-qt", rpm:"scim-bridge-qt~0.4.13~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.1.14~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.1.14~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~1.1.14~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.1.14~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-spellchecker", rpm:"seamonkey-spellchecker~1.1.14~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~1.1.14~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"silc-toolkit", rpm:"silc-toolkit~1.1.2~14.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"silc-toolkit-devel", rpm:"silc-toolkit-devel~1.1.2~14.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"smartlink-softmodem-kmp-bigsmp", rpm:"smartlink-softmodem-kmp-bigsmp~2.9.10_2.6.22.18_0.2~148.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"smartlink-softmodem-kmp-default", rpm:"smartlink-softmodem-kmp-default~2.9.10_2.6.22.18_0.2~148.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"smartmontools", rpm:"smartmontools~5.37~15.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.4.1~19.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.2.3~10.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"splashy", rpm:"splashy~0.3.3~45.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"splashy-devel", rpm:"splashy-devel~0.3.3~45.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"splashy-themes", rpm:"splashy-themes~0.3.3~45.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"sqlite2", rpm:"sqlite2~2.8.17~88.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"sqlite2-devel", rpm:"sqlite2-devel~2.8.17~88.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squid", rpm:"squid~2.6.STABLE14~23.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.6.9p2~23.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"sysconfig", rpm:"sysconfig~0.70.2~4.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"syslog-ng", rpm:"syslog-ng~1.6.12~33.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"sysprof-kmp-bigsmp", rpm:"sysprof-kmp-bigsmp~1.0.8_2.6.22.18_0.2~70.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"sysprof-kmp-debug", rpm:"sysprof-kmp-debug~1.0.8_2.6.22.18_0.2~70.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"sysprof-kmp-default", rpm:"sysprof-kmp-default~1.0.8_2.6.22.18_0.2~70.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"t1lib", rpm:"t1lib~5.1.1~15.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"t1lib-devel", rpm:"t1lib-devel~5.1.1~15.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tcsh", rpm:"tcsh~6.15.00~20.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-bin", rpm:"texlive-bin~2007~68.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-bin-cjk", rpm:"texlive-bin-cjk~2007~68.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-bin-devel", rpm:"texlive-bin-devel~2007~68.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-bin-dvilj", rpm:"texlive-bin-dvilj~2007~68.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-bin-latex", rpm:"texlive-bin-latex~2007~68.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-bin-metapost", rpm:"texlive-bin-metapost~2007~68.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-bin-omega", rpm:"texlive-bin-omega~2007~68.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-bin-xetex", rpm:"texlive-bin-xetex~2007~68.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tiff", rpm:"tiff~3.8.2~68.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"timezone", rpm:"timezone~2008h~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tk", rpm:"tk~8.4.15~25.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tk-devel", rpm:"tk-devel~8.4.15~25.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tkimg", rpm:"tkimg~1.3~125.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomboy", rpm:"tomboy~0.8.0~9.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tpctl-kmp-bigsmp", rpm:"tpctl-kmp-bigsmp~4.17_2.6.22.18_0.2~131.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tpctl-kmp-debug", rpm:"tpctl-kmp-debug~4.17_2.6.22.18_0.2~131.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tpctl-kmp-default", rpm:"tpctl-kmp-default~4.17_2.6.22.18_0.2~131.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"transfig", rpm:"transfig~3.2.5~28.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"unzip", rpm:"unzip~5.52~77.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"util-linux", rpm:"util-linux~2.12r+2.13rc2+git20070725~24.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"uvcvideo-kmp-bigsmp", rpm:"uvcvideo-kmp-bigsmp~r117_2.6.22.18_0.2~1.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"uvcvideo-kmp-debug", rpm:"uvcvideo-kmp-debug~r117_2.6.22.18_0.2~1.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"uvcvideo-kmp-default", rpm:"uvcvideo-kmp-default~r117_2.6.22.18_0.2~1.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"uvcvideo-kmp-xen", rpm:"uvcvideo-kmp-xen~r117_2.6.22.18_0.2~1.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"uvcvideo-kmp-xenpae", rpm:"uvcvideo-kmp-xenpae~r117_2.6.22.18_0.2~1.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"valgrind", rpm:"valgrind~3.2.3~57.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"valgrind-devel", rpm:"valgrind-devel~3.2.3~57.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"viewvc", rpm:"viewvc~1.0.4~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vim", rpm:"vim~7.1~44.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vim-base", rpm:"vim-base~7.1~44.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~7.1~44.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~7.1~44.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virt-manager", rpm:"virt-manager~0.4.0~68.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~1.5.2~10.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~1.5.2~10.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox-kmp-bigsmp", rpm:"virtualbox-kmp-bigsmp~1.5.2_2.6.22.18_0.2~10.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox-kmp-debug", rpm:"virtualbox-kmp-debug~1.5.2_2.6.22.18_0.2~10.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox-kmp-default", rpm:"virtualbox-kmp-default~1.5.2_2.6.22.18_0.2~10.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vorbis-tools", rpm:"vorbis-tools~1.1.1~112.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vpnc", rpm:"vpnc~0.3.3~75.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireless-tools", rpm:"wireless-tools~29pre22~17.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~0.99.6~31.13", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~0.99.6~31.13", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wlan-ng-kmp-bigsmp", rpm:"wlan-ng-kmp-bigsmp~0.2.8_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wlan-ng-kmp-debug", rpm:"wlan-ng-kmp-debug~0.2.8_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wlan-ng-kmp-default", rpm:"wlan-ng-kmp-default~0.2.8_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wlan-ng-kmp-xen", rpm:"wlan-ng-kmp-xen~0.2.8_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wlan-ng-kmp-xenpae", rpm:"wlan-ng-kmp-xenpae~0.2.8_2.6.22.18_0.2~37.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wvdial", rpm:"wvdial~1.56~22.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xemacs", rpm:"xemacs~21.5.28.20070807~24.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xemacs-el", rpm:"xemacs-el~21.5.28.20070807~24.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xemacs-info", rpm:"xemacs-info~21.5.28.20070807~24.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen", rpm:"xen~3.1.0_15042~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.1.0_15042~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~3.1.0_15042~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~3.1.0_15042~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.1.0_15042~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~3.1.0_15042~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~3.1.0_15042~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-tools-ioemu", rpm:"xen-tools-ioemu~3.1.0_15042~51.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xfce4-panel", rpm:"xfce4-panel~4.4.1~61.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xfce4-panel-devel", rpm:"xfce4-panel-devel~4.4.1~61.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xfsprogs", rpm:"xfsprogs~2.9.4~17.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xfsprogs-devel", rpm:"xfsprogs-devel~2.9.4~17.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xgl", rpm:"xgl~git_070104~77.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-devel", rpm:"xine-devel~1.1.8~14.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-extra", rpm:"xine-extra~1.1.8~14.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-lib", rpm:"xine-lib~1.1.8~14.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-ui", rpm:"xine-ui~0.99.5~62.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xorg-x11", rpm:"xorg-x11~7.2~135.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~7.1~91.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xorg-x11-devel", rpm:"xorg-x11-devel~7.2~103.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xorg-x11-doc", rpm:"xorg-x11-doc~7.2~56.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xorg-x11-driver-video", rpm:"xorg-x11-driver-video~7.2~189.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xorg-x11-driver-virtualbox", rpm:"xorg-x11-driver-virtualbox~1.5.2~10.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xorg-x11-libs", rpm:"xorg-x11-libs~7.2~103.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xorg-x11-libxcb", rpm:"xorg-x11-libxcb~7.2~51.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xorg-x11-libxcb-devel", rpm:"xorg-x11-libxcb-devel~7.2~51.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~7.2~143.13", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~7.2~143.13", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~7.2~143.13", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~3.02~19.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf-tools", rpm:"xpdf-tools~3.02~19.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xscreensaver", rpm:"xscreensaver~5.03~24.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xterm", rpm:"xterm~229~17.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"yast2-core", rpm:"yast2-core~2.15.13~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"yast2-core-devel", rpm:"yast2-core-devel~2.15.13~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"yast2-gtk", rpm:"yast2-gtk~2.15.9~34.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"yast2-profile-manager", rpm:"yast2-profile-manager~2.15.1~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"yauap", rpm:"yauap~0.2.1~21.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"zypper", rpm:"zypper~0.8.26~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
