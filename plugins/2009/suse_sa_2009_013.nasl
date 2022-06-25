# OpenVAS Vulnerability Test
# $Id: suse_sa_2009_013.nasl 6668 2017-07-11 13:34:29Z cfischer $
# Description: Auto-generated from advisory SUSE-SA:2009:013 (dbus-1, hal, NetworkManager, PackageKit, ...)
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
tag_insight = "Joachim Breitner discovered that the default DBus system policy was
too permissive. In fact the default policy was to allow all calls on
the bus. Many services expected that the default was to deny
everything and therefore only installed rules that explicitly allow
certain calls with the result that intended access control for some
services was not applied.

The updated DBus package now installs a new policy that denies
access by default. Unfortunately some DBus services actually relied
on the insecure default setting and break with the new policy.
Therefore quite a number of packages is affected by this DBus
update.

The updated DBus daemon now logs access violations via syslog. If
you see log entries about rejected messages of type method_call
during normal operation the application that caused it likely needs
an updated DBus policy. Please contact the application vendor in
this case.";
tag_solution = "Update your system with the packages as indicated in
the referenced security advisory.

https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:013";
tag_summary = "The remote host is missing updates announced in
advisory SUSE-SA:2009:013.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311872");
 script_version("$Revision: 6668 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:34:29 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
 script_cve_id("CVE-2008-4311", "CVE-2009-0365", "CVE-2009-0578");
 script_tag(name:"cvss_base", value:"6.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:C/A:C");
 script_name("SuSE Security Advisory SUSE-SA:2009:013 (dbus-1, hal, NetworkManager, PackageKit, ...)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"ConsoleKit-debuginfo", rpm:"ConsoleKit-debuginfo~0.2.10~60.26.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ConsoleKit-debugsource", rpm:"ConsoleKit-debugsource~0.2.10~60.26.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PackageKit-debuginfo", rpm:"PackageKit-debuginfo~0.3.11~1.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PackageKit-debugsource", rpm:"PackageKit-debugsource~0.3.11~1.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PolicyKit-debuginfo", rpm:"PolicyKit-debuginfo~0.9~13.17.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PolicyKit-debugsource", rpm:"PolicyKit-debugsource~0.9~13.17.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bluez-debuginfo", rpm:"bluez-debuginfo~4.22~6.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bluez-debugsource", rpm:"bluez-debugsource~4.22~6.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-debuginfo", rpm:"dbus-1-debuginfo~1.2.10~5.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-debugsource", rpm:"dbus-1-debugsource~1.2.10~5.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-debuginfo", rpm:"dbus-1-glib-debuginfo~0.76~32.33.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-debugsource", rpm:"dbus-1-glib-debugsource~0.76~32.33.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-python-debuginfo", rpm:"dbus-1-python-debuginfo~0.83.0~22.22.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-python-debugsource", rpm:"dbus-1-python-debugsource~0.83.0~22.22.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-debuginfo", rpm:"dbus-1-qt3-debuginfo~0.62~221.222.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-debugsource", rpm:"dbus-1-qt3-debugsource~0.62~221.222.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-x11-debuginfo", rpm:"dbus-1-x11-debuginfo~1.2.10~5.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-x11-debugsource", rpm:"dbus-1-x11-debugsource~1.2.10~5.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-debuginfo", rpm:"hal-debuginfo~0.5.12~10.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-debugsource", rpm:"hal-debugsource~0.5.12~10.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pommed-debuginfo", rpm:"pommed-debuginfo~1.22~1.15.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pommed-debugsource", rpm:"pommed-debugsource~1.22~1.15.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ConsoleKit", rpm:"ConsoleKit~0.2.10~60.26.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ConsoleKit-devel", rpm:"ConsoleKit-devel~0.2.10~60.26.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ConsoleKit-x11", rpm:"ConsoleKit-x11~0.2.10~60.26.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PackageKit", rpm:"PackageKit~0.3.11~1.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PackageKit-devel", rpm:"PackageKit-devel~0.3.11~1.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PackageKit-lang", rpm:"PackageKit-lang~0.3.11~1.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PolicyKit", rpm:"PolicyKit~0.9~13.17.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PolicyKit-devel", rpm:"PolicyKit-devel~0.9~13.17.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bluez", rpm:"bluez~4.22~6.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bluez-alsa", rpm:"bluez-alsa~4.22~6.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bluez-compat", rpm:"bluez-compat~4.22~6.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bluez-cups", rpm:"bluez-cups~4.22~6.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bluez-devel", rpm:"bluez-devel~4.22~6.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bluez-test", rpm:"bluez-test~4.22~6.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1", rpm:"dbus-1~1.2.10~5.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-devel", rpm:"dbus-1-devel~1.2.10~5.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-devel-doc", rpm:"dbus-1-devel-doc~1.2.10~5.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib", rpm:"dbus-1-glib~0.76~32.33.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-devel", rpm:"dbus-1-glib-devel~0.76~32.33.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-doc", rpm:"dbus-1-glib-doc~0.76~32.33.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-mono", rpm:"dbus-1-mono~0.63~118.117.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-python", rpm:"dbus-1-python~0.83.0~22.22.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-python-devel", rpm:"dbus-1-python-devel~0.83.0~22.22.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3", rpm:"dbus-1-qt3~0.62~221.222.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-devel", rpm:"dbus-1-qt3-devel~0.62~221.222.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-x11", rpm:"dbus-1-x11~1.2.10~5.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gpomme", rpm:"gpomme~1.22~1.15.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal", rpm:"hal~0.5.12~10.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-devel", rpm:"hal-devel~0.5.12~10.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libbluetooth3", rpm:"libbluetooth3~4.22~6.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpackagekit-glib10", rpm:"libpackagekit-glib10~0.3.11~1.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpackagekit-glib10-devel", rpm:"libpackagekit-glib10-devel~0.3.11~1.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpackagekit-qt10", rpm:"libpackagekit-qt10~0.3.11~1.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpackagekit-qt10-devel", rpm:"libpackagekit-qt10-devel~0.3.11~1.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pommed", rpm:"pommed~1.22~1.15.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wmpomme", rpm:"wmpomme~1.22~1.15.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ConsoleKit-debuginfo", rpm:"ConsoleKit-debuginfo~0.2.10~14.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ConsoleKit-debugsource", rpm:"ConsoleKit-debugsource~0.2.10~14.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PackageKit-debuginfo", rpm:"PackageKit-debuginfo~0.2.1~15.10", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PackageKit-debugsource", rpm:"PackageKit-debugsource~0.2.1~15.10", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PolicyKit-debuginfo", rpm:"PolicyKit-debuginfo~0.8~14.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PolicyKit-debugsource", rpm:"PolicyKit-debugsource~0.8~14.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-debuginfo", rpm:"dbus-1-debuginfo~1.2.1~15.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-debugsource", rpm:"dbus-1-debugsource~1.2.1~15.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-debuginfo", rpm:"dbus-1-glib-debuginfo~0.74~88.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-debugsource", rpm:"dbus-1-glib-debugsource~0.74~88.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-python-debuginfo", rpm:"dbus-1-python-debuginfo~0.82.4~49.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-python-debugsource", rpm:"dbus-1-python-debugsource~0.82.4~49.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-debuginfo", rpm:"dbus-1-qt3-debuginfo~0.62~179.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-debugsource", rpm:"dbus-1-qt3-debugsource~0.62~179.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-x11-debuginfo", rpm:"dbus-1-x11-debuginfo~1.2.1~18.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-x11-debugsource", rpm:"dbus-1-x11-debugsource~1.2.1~18.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-debuginfo", rpm:"hal-debuginfo~0.5.11~8.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-debugsource", rpm:"hal-debugsource~0.5.11~8.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pommed-debuginfo", rpm:"pommed-debuginfo~1.15~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pommed-debugsource", rpm:"pommed-debugsource~1.15~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"powersave-debuginfo", rpm:"powersave-debuginfo~0.15.20~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"powersave-debugsource", rpm:"powersave-debugsource~0.15.20~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ConsoleKit", rpm:"ConsoleKit~0.2.10~14.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ConsoleKit-devel", rpm:"ConsoleKit-devel~0.2.10~14.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ConsoleKit-x11", rpm:"ConsoleKit-x11~0.2.10~14.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PackageKit", rpm:"PackageKit~0.2.1~15.10", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PackageKit-devel", rpm:"PackageKit-devel~0.2.1~15.10", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PolicyKit", rpm:"PolicyKit~0.8~14.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PolicyKit-devel", rpm:"PolicyKit-devel~0.8~14.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1", rpm:"dbus-1~1.2.1~15.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-devel", rpm:"dbus-1-devel~1.2.1~15.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-devel-doc", rpm:"dbus-1-devel-doc~1.2.1~15.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib", rpm:"dbus-1-glib~0.74~88.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-devel", rpm:"dbus-1-glib-devel~0.74~88.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-doc", rpm:"dbus-1-glib-doc~0.74~88.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-mono", rpm:"dbus-1-mono~0.63~154.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-python", rpm:"dbus-1-python~0.82.4~49.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-python-devel", rpm:"dbus-1-python-devel~0.82.4~49.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3", rpm:"dbus-1-qt3~0.62~179.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-devel", rpm:"dbus-1-qt3-devel~0.62~179.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-x11", rpm:"dbus-1-x11~1.2.1~18.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gpomme", rpm:"gpomme~1.15~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal", rpm:"hal~0.5.11~8.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-devel", rpm:"hal-devel~0.5.11~8.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pommed", rpm:"pommed~1.15~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"powersave", rpm:"powersave~0.15.20~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"powersave-devel", rpm:"powersave-devel~0.15.20~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"powersave-libs", rpm:"powersave-libs~0.15.20~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wmpomme", rpm:"wmpomme~1.15~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1", rpm:"dbus-1~1.0.2~59.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-devel", rpm:"dbus-1-devel~1.0.2~59.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-devel-doc", rpm:"dbus-1-devel-doc~1.0.2~59.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib", rpm:"dbus-1-glib~0.74~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-devel", rpm:"dbus-1-glib-devel~0.74~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-doc", rpm:"dbus-1-glib-doc~0.74~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-mono", rpm:"dbus-1-mono~0.63~90.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-python", rpm:"dbus-1-python~0.82.0~28.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-python-devel", rpm:"dbus-1-python-devel~0.82.0~28.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3", rpm:"dbus-1-qt3~0.62~110.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-devel", rpm:"dbus-1-qt3-devel~0.62~110.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-x11", rpm:"dbus-1-x11~1.0.2~67.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gpomme", rpm:"gpomme~1.9~4.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal", rpm:"hal~0.5.9_git20070831~13.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-devel", rpm:"hal-devel~0.5.9_git20070831~13.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pommed", rpm:"pommed~1.9~4.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"powersave", rpm:"powersave~0.15.17~10.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"powersave-devel", rpm:"powersave-devel~0.15.17~10.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"powersave-libs", rpm:"powersave-libs~0.15.17~10.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wmpomme", rpm:"wmpomme~1.9~4.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-debuginfo-64bit", rpm:"dbus-1-debuginfo-64bit~1.2.10~5.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-debuginfo-64bit", rpm:"dbus-1-glib-debuginfo-64bit~0.76~32.33.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-debuginfo-64bit", rpm:"hal-debuginfo-64bit~0.5.12~10.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ConsoleKit-64bit", rpm:"ConsoleKit-64bit~0.2.10~60.26.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PolicyKit-64bit", rpm:"PolicyKit-64bit~0.9~13.17.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-64bit", rpm:"dbus-1-64bit~1.2.10~5.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-64bit", rpm:"dbus-1-glib-64bit~0.76~32.33.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-64bit", rpm:"dbus-1-qt3-64bit~0.62~221.222.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-64bit", rpm:"hal-64bit~0.5.12~10.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ConsoleKit-64bit", rpm:"ConsoleKit-64bit~0.2.10~14.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PolicyKit-64bit", rpm:"PolicyKit-64bit~0.8~14.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-64bit", rpm:"dbus-1-64bit~1.2.1~15.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-64bit", rpm:"dbus-1-glib-64bit~0.74~88.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-64bit", rpm:"dbus-1-qt3-64bit~0.62~179.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-64bit", rpm:"hal-64bit~0.5.11~8.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"powersave-libs-64bit", rpm:"powersave-libs-64bit~0.15.20~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-64bit", rpm:"dbus-1-64bit~1.0.2~59.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-64bit", rpm:"dbus-1-glib-64bit~0.74~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-64bit", rpm:"dbus-1-qt3-64bit~0.62~110.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-64bit", rpm:"hal-64bit~0.5.9_git20070831~13.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"powersave-libs-64bit", rpm:"powersave-libs-64bit~0.15.17~10.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-debuginfo-32bit", rpm:"dbus-1-debuginfo-32bit~1.2.10~5.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-debuginfo-32bit", rpm:"dbus-1-glib-debuginfo-32bit~0.76~32.33.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-debuginfo-32bit", rpm:"hal-debuginfo-32bit~0.5.12~10.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ConsoleKit-32bit", rpm:"ConsoleKit-32bit~0.2.10~60.26.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PolicyKit-32bit", rpm:"PolicyKit-32bit~0.9~13.17.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-32bit", rpm:"dbus-1-32bit~1.2.10~5.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-32bit", rpm:"dbus-1-glib-32bit~0.76~32.33.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-32bit", rpm:"dbus-1-qt3-32bit~0.62~221.222.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-32bit", rpm:"hal-32bit~0.5.12~10.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ConsoleKit-32bit", rpm:"ConsoleKit-32bit~0.2.10~14.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"PolicyKit-32bit", rpm:"PolicyKit-32bit~0.8~14.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-32bit", rpm:"dbus-1-32bit~1.2.1~15.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-32bit", rpm:"dbus-1-glib-32bit~0.74~88.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-32bit", rpm:"dbus-1-qt3-32bit~0.62~179.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-32bit", rpm:"hal-32bit~0.5.11~8.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"powersave-libs-32bit", rpm:"powersave-libs-32bit~0.15.20~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-32bit", rpm:"dbus-1-32bit~1.0.2~59.8", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-glib-32bit", rpm:"dbus-1-glib-32bit~0.74~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dbus-1-qt3-32bit", rpm:"dbus-1-qt3-32bit~0.62~110.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hal-32bit", rpm:"hal-32bit~0.5.9_git20070831~13.5", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"powersave-libs-32bit", rpm:"powersave-libs-32bit~0.15.17~10.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
