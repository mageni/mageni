# OpenVAS Vulnerability Test
# $Id: suse_sr_2009_012.nasl 6668 2017-07-11 13:34:29Z cfischer $
# Description: Auto-generated from advisory SUSE-SR:2009:012
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
advisory SUSE-SR:2009:012.  SuSE Security Summaries are short
on detail when it comes to the names of packages affected by
a particular bug. Because of this, while this test will detect
out of date packages, it cannot tell you what bugs impact
which packages, or vice versa.";

tag_solution = "Update all out of date packages.";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308069");
 script_version("$Revision: 6668 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:34:29 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-07-06 20:36:15 +0200 (Mon, 06 Jul 2009)");
 script_cve_id("CVE-2008-5515", "CVE-2008-6123", "CVE-2009-0033", "CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0198", "CVE-2009-0509", "CVE-2009-0510", "CVE-2009-0511", "CVE-2009-0512", "CVE-2009-0580", "CVE-2009-0663", "CVE-2009-0749", "CVE-2009-0755", "CVE-2009-0756", "CVE-2009-0781", "CVE-2009-0783", "CVE-2009-0791", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-0949", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-1194", "CVE-2009-1271", "CVE-2009-1272", "CVE-2009-1341", "CVE-2009-1386", "CVE-2009-1387", "CVE-2009-1391", "CVE-2009-1438", "CVE-2009-1572", "CVE-2009-1574", "CVE-2009-1632", "CVE-2009-1648", "CVE-2009-1855", "CVE-2009-1856", "CVE-2009-1857", "CVE-2009-1858", "CVE-2009-1859", "CVE-2009-1861", "CVE-2009-1882", "CVE-2009-1957", "CVE-2009-1958", "CVE-2009-1959");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("SuSE Security Summary SUSE-SR:2009:012");



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
if ((res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.2.5~4.25.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.2.5~4.25.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.4.3.6~5.4.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.4.3.6~5.4.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~6.4.3.6~5.4.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.0.11~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~3.0.11~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.0.11~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.6~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.95.2~1.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.95.2~1.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fontconfig", rpm:"fontconfig~2.6.0~8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fontconfig-devel", rpm:"fontconfig-devel~2.6.0~8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-control-center", rpm:"gnome-control-center~2.24.0.1~3.21.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-control-center-devel", rpm:"gnome-control-center-devel~2.24.0.1~3.21.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-control-center-lang", rpm:"gnome-control-center-lang~2.24.0.1~3.21.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-desktop", rpm:"gnome-desktop~2.24.1~2.18.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-desktop-devel", rpm:"gnome-desktop-devel~2.24.1~2.18.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-desktop-doc", rpm:"gnome-desktop-doc~2.24.1~2.18.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-desktop-lang", rpm:"gnome-desktop-lang~2.24.1~2.18.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-panel", rpm:"gnome-panel~2.24.1~2.27.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-panel-devel", rpm:"gnome-panel-devel~2.24.1~2.27.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-panel-doc", rpm:"gnome-panel-doc~2.24.1~2.27.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-panel-extras", rpm:"gnome-panel-extras~2.24.1~2.27.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-panel-lang", rpm:"gnome-panel-lang~2.24.1~2.27.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-settings-daemon", rpm:"gnome-settings-daemon~2.24.0~3.21.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-settings-daemon-devel", rpm:"gnome-settings-daemon-devel~2.24.0~3.21.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-settings-daemon-lang", rpm:"gnome-settings-daemon-lang~2.24.0~3.21.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad", rpm:"gstreamer-0_10-plugins-bad~0.10.8~6.6.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad-devel", rpm:"gstreamer-0_10-plugins-bad-devel~0.10.8~6.6.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad-doc", rpm:"gstreamer-0_10-plugins-bad-doc~0.10.8~6.6.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad-lang", rpm:"gstreamer-0_10-plugins-bad-lang~0.10.8~6.6.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good", rpm:"gstreamer-0_10-plugins-good~0.10.10~3.22.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-doc", rpm:"gstreamer-0_10-plugins-good-doc~0.10.10~3.22.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-extra", rpm:"gstreamer-0_10-plugins-good-extra~0.10.10~3.22.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-lang", rpm:"gstreamer-0_10-plugins-good-lang~0.10.10~3.22.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ifolder3", rpm:"ifolder3~3.7.2.9141.1~3.3.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ipsec-tools", rpm:"ipsec-tools~0.7.1~10.49.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"irssi", rpm:"irssi~0.8.12~30.70.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"irssi-devel", rpm:"irssi-devel~0.8.12~30.70.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun", rpm:"java-1_5_0-sun~1.5.0_update19~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-alsa", rpm:"java-1_5_0-sun-alsa~1.5.0_update19~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-devel", rpm:"java-1_5_0-sun-devel~1.5.0_update19~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-jdbc", rpm:"java-1_5_0-sun-jdbc~1.5.0_update19~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-plugin", rpm:"java-1_5_0-sun-plugin~1.5.0_update19~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-src", rpm:"java-1_5_0-sun-src~1.5.0_update19~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"klamav", rpm:"klamav~0.46~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagick++-devel", rpm:"libGraphicsMagick++-devel~1.2.5~4.25.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagick++2", rpm:"libGraphicsMagick++2~1.2.5~4.25.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagick2", rpm:"libGraphicsMagick2~1.2.5~4.25.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagickWand1", rpm:"libGraphicsMagickWand1~1.2.5~4.25.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~6.4.3.6~5.4.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick++1", rpm:"libMagick++1~6.4.3.6~5.4.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagickCore1", rpm:"libMagickCore1~6.4.3.6~5.4.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagickWand1", rpm:"libMagickWand1~6.4.3.6~5.4.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnome-desktop-2-7", rpm:"libgnome-desktop-2-7~2.24.1~2.18.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgstapp-0_10-0", rpm:"libgstapp-0_10-0~0.10.8~6.6.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnotify1", rpm:"libnotify1~0.4.4~173.8", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnsssharedhelper0", rpm:"libnsssharedhelper0~1.0.4~1.5", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8h~28.10.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8h~28.10.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpoppler4", rpm:"libpoppler4~0.10.1~1.6.10", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner190", rpm:"mozilla-xulrunner190~1.9.0.11~1.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner190-devel", rpm:"mozilla-xulrunner190-devel~1.9.0.11~1.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs", rpm:"mozilla-xulrunner190-gnomevfs~1.9.0.11~1.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner190-translations", rpm:"mozilla-xulrunner190-translations~1.9.0.11~1.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nautilus-ifolder3", rpm:"nautilus-ifolder3~3.7.2.9141.1~2.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novell-ifolder-client-plugins", rpm:"novell-ifolder-client-plugins~3.7.2.9141.1~2.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novell-ipsec-tools", rpm:"novell-ipsec-tools~0.7.1~2.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novell-ipsec-tools-devel", rpm:"novell-ipsec-tools-devel~0.7.1~2.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspluginwrapper", rpm:"nspluginwrapper~1.2.2~2.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8h~28.10.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8h~28.10.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"osc", rpm:"osc~0.120~1.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl", rpm:"perl~5.10.0~62.18.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-GraphicsMagick", rpm:"perl-GraphicsMagick~1.2.5~4.25.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~6.4.3.6~5.4.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-base", rpm:"perl-base~5.10.0~62.18.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-doc", rpm:"perl-doc~5.10.0~62.18.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-xpcom190", rpm:"python-xpcom190~1.9.0.11~1.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.1.16~1.1.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.1.16~1.1.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~1.1.16~1.1.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.1.16~1.1.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-spellchecker", rpm:"seamonkey-spellchecker~1.1.16~1.1.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~1.1.16~1.1.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"simias", rpm:"simias~1.8.2.9141.1~3.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"startup-notification", rpm:"startup-notification~0.9~59.61", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"startup-notification-devel", rpm:"startup-notification-devel~0.9~59.61", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~0.6.4~15.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wpa_supplicant-gui", rpm:"wpa_supplicant-gui~0.6.4~15.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.1.11~29.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.1.11~29.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.4.0.4~20.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.4.0.4~20.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~6.4.0.4~20.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.0.11~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.0.11~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.6~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.95.2~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.95.2~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad", rpm:"gstreamer-0_10-plugins-bad~0.10.6~36.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad-devel", rpm:"gstreamer-0_10-plugins-bad-devel~0.10.6~36.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad-doc", rpm:"gstreamer-0_10-plugins-bad-doc~0.10.6~36.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad-lang", rpm:"gstreamer-0_10-plugins-bad-lang~0.10.6~36.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good", rpm:"gstreamer-0_10-plugins-good~0.10.7~38.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-doc", rpm:"gstreamer-0_10-plugins-good-doc~0.10.7~38.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-extra", rpm:"gstreamer-0_10-plugins-good-extra~0.10.7~38.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-lang", rpm:"gstreamer-0_10-plugins-good-lang~0.10.7~38.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ipsec-tools", rpm:"ipsec-tools~0.7~61.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"irssi", rpm:"irssi~0.8.12~49.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"irssi-devel", rpm:"irssi-devel~0.8.12~49.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun", rpm:"java-1_5_0-sun~1.5.0_update19~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-alsa", rpm:"java-1_5_0-sun-alsa~1.5.0_update19~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-demo", rpm:"java-1_5_0-sun-demo~1.5.0_update19~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-devel", rpm:"java-1_5_0-sun-devel~1.5.0_update19~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-jdbc", rpm:"java-1_5_0-sun-jdbc~1.5.0_update19~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-plugin", rpm:"java-1_5_0-sun-plugin~1.5.0_update19~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-src", rpm:"java-1_5_0-sun-src~1.5.0_update19~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"klamav", rpm:"klamav~0.46~0.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagick++-devel", rpm:"libGraphicsMagick++-devel~1.1.11~29.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagick++1", rpm:"libGraphicsMagick++1~1.1.11~29.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagick1", rpm:"libGraphicsMagick1~1.1.11~29.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagickWand0", rpm:"libGraphicsMagickWand0~1.1.11~29.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~6.4.0.4~20.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick++1", rpm:"libMagick++1~6.4.0.4~20.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagickCore1", rpm:"libMagickCore1~6.4.0.4~20.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagickWand1", rpm:"libMagickWand1~6.4.0.4~20.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgstapp-0_10-0", rpm:"libgstapp-0_10-0~0.10.6~36.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8g~47.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8g~47.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpoppler3", rpm:"libpoppler3~0.8.2~1.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner190", rpm:"mozilla-xulrunner190~1.9.0.11~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner190-devel", rpm:"mozilla-xulrunner190-devel~1.9.0.11~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs", rpm:"mozilla-xulrunner190-gnomevfs~1.9.0.11~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-xulrunner190-translations", rpm:"mozilla-xulrunner190-translations~1.9.0.11~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novell-ipsec-tools", rpm:"novell-ipsec-tools~0.6.3~183.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novell-ipsec-tools-devel", rpm:"novell-ipsec-tools-devel~0.6.3~183.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8g~47.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-certs", rpm:"openssl-certs~0.9.8g~47.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8g~47.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"osc", rpm:"osc~0.120~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl", rpm:"perl~5.10.0~37.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-GraphicsMagick", rpm:"perl-GraphicsMagick~1.1.11~29.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~6.4.0.4~20.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-base", rpm:"perl-base~5.10.0~37.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-doc", rpm:"perl-doc~5.10.0~37.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.1.16~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.1.16~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~1.1.16~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.1.16~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-spellchecker", rpm:"seamonkey-spellchecker~1.1.16~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~1.1.16~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"yast2-qt-pkg", rpm:"yast2-qt-pkg~2.16.49~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.1.8~20.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.1.8~20.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.3.5.10~2.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.3.5.10~2.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~6.3.5.10~2.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.6~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.95.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.95.2~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer010-plugins-bad", rpm:"gstreamer010-plugins-bad~0.10.5~36.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer010-plugins-bad-devel", rpm:"gstreamer010-plugins-bad-devel~0.10.5~36.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer010-plugins-bad-doc", rpm:"gstreamer010-plugins-bad-doc~0.10.5~36.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer010-plugins-good", rpm:"gstreamer010-plugins-good~0.10.6~41.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer010-plugins-good-doc", rpm:"gstreamer010-plugins-good-doc~0.10.6~41.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer010-plugins-good-extra", rpm:"gstreamer010-plugins-good-extra~0.10.6~41.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ipsec-tools", rpm:"ipsec-tools~0.6.5~104.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"irssi", rpm:"irssi~0.8.11~19.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"irssi-devel", rpm:"irssi-devel~0.8.11~19.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun", rpm:"java-1_5_0-sun~1.5.0_update19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-alsa", rpm:"java-1_5_0-sun-alsa~1.5.0_update19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-demo", rpm:"java-1_5_0-sun-demo~1.5.0_update19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-devel", rpm:"java-1_5_0-sun-devel~1.5.0_update19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-jdbc", rpm:"java-1_5_0-sun-jdbc~1.5.0_update19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-plugin", rpm:"java-1_5_0-sun-plugin~1.5.0_update19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_5_0-sun-src", rpm:"java-1_5_0-sun-src~1.5.0_update19~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"klamav", rpm:"klamav~0.46~0.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagick++-devel", rpm:"libGraphicsMagick++-devel~1.1.8~20.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagick++1", rpm:"libGraphicsMagick++1~1.1.8~20.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagick1", rpm:"libGraphicsMagick1~1.1.8~20.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libGraphicsMagickWand0", rpm:"libGraphicsMagickWand0~1.1.8~20.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~6.3.5.10~2.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick++10", rpm:"libMagick++10~6.3.5.10~2.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick10", rpm:"libMagick10~6.3.5.10~2.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libWand10", rpm:"libWand10~6.3.5.10~2.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8e~45.13", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8e~45.13", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novell-ipsec-tools", rpm:"novell-ipsec-tools~0.6.3~114.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"novell-ipsec-tools-devel", rpm:"novell-ipsec-tools-devel~0.6.3~114.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~45.13", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-certs", rpm:"openssl-certs~0.9.8e~45.13", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8e~45.13", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"osc", rpm:"osc~0.120~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Compress-Raw-Zlib", rpm:"perl-Compress-Raw-Zlib~2.005~17.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-DBD-Pg", rpm:"perl-DBD-Pg~1.49~76.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-GraphicsMagick", rpm:"perl-GraphicsMagick~1.1.8~20.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~6.3.5.10~2.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.5.4~101.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-devel", rpm:"poppler-devel~0.5.4~101.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-doc", rpm:"poppler-doc~0.5.4~101.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-glib", rpm:"poppler-glib~0.5.4~101.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-qt", rpm:"poppler-qt~0.5.4~101.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-qt4", rpm:"poppler-qt4~0.5.4~101.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~0.5.4~101.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.1.16~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.1.16~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~1.1.16~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.1.16~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-spellchecker", rpm:"seamonkey-spellchecker~1.1.16~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~1.1.16~1.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
