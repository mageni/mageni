# OpenVAS Vulnerability Test
# $Id: suse_sr_2009_011.nasl 6668 2017-07-11 13:34:29Z cfischer $
# Description: Auto-generated from advisory SUSE-SR:2009:011
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
advisory SUSE-SR:2009:011.  SuSE Security Summaries are short
on detail when it comes to the names of packages affected by
a particular bug. Because of this, while this test will detect
out of date packages, it cannot tell you what bugs impact
which packages, or vice versa.";

tag_solution = "Update all out of date packages.";
                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311290");
 script_version("$Revision: 6668 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:34:29 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-15 19:20:43 +0200 (Mon, 15 Jun 2009)");
 script_cve_id("CVE-2007-5400", "CVE-2007-6725", "CVE-2008-6123", "CVE-2008-6679", "CVE-2009-0159", "CVE-2009-0196", "CVE-2009-0241", "CVE-2009-0688", "CVE-2009-0792", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1107", "CVE-2009-1210", "CVE-2009-1252", "CVE-2009-1266", "CVE-2009-1267", "CVE-2009-1268", "CVE-2009-1269", "CVE-2009-1274", "CVE-2009-1364", "CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379", "CVE-2009-1492", "CVE-2009-1493");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("SuSE Security Summary SUSE-SR:2009:011");



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
if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.5~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_security2", rpm:"apache2-mod_security2~2.5.6~1.25.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"aufs-kmp-debug", rpm:"aufs-kmp-debug~cvs20081020_2.6.27.23_0.1~1.32.10", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"aufs-kmp-trace", rpm:"aufs-kmp-trace~cvs20081020_2.6.27.23_0.1~1.32.10", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"brocade-bfa-kmp-debug", rpm:"brocade-bfa-kmp-debug~1.1.0.2_2.6.27.23_0.1~1.7.8", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"brocade-bfa-kmp-trace", rpm:"brocade-bfa-kmp-trace~1.1.0.2_2.6.27.23_0.1~1.7.8", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~182.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-crammd5", rpm:"cyrus-sasl-crammd5~2.1.22~182.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-devel", rpm:"cyrus-sasl-devel~2.1.22~182.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-digestmd5", rpm:"cyrus-sasl-digestmd5~2.1.22~182.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-gssapi", rpm:"cyrus-sasl-gssapi~2.1.22~182.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-ntlm", rpm:"cyrus-sasl-ntlm~2.1.22~182.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-otp", rpm:"cyrus-sasl-otp~2.1.22~182.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-plain", rpm:"cyrus-sasl-plain~2.1.22~182.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dazuko-kmp-debug", rpm:"dazuko-kmp-debug~2.3.6_2.6.27.23_0.1~1.49.8", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dazuko-kmp-trace", rpm:"dazuko-kmp-trace~2.3.6_2.6.27.23_0.1~1.49.8", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dos2unix", rpm:"dos2unix~3.1~437.37.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"drbd-kmp-debug", rpm:"drbd-kmp-debug~8.2.7_2.6.27.23_0.1~1.19.6", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"drbd-kmp-trace", rpm:"drbd-kmp-trace~8.2.7_2.6.27.23_0.1~1.19.6", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-monitor-core", rpm:"ganglia-monitor-core~2.5.7~172.40.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-monitor-core-devel", rpm:"ganglia-monitor-core-devel~2.5.7~172.40.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-monitor-core-gmetad", rpm:"ganglia-monitor-core-gmetad~2.5.7~172.40.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-monitor-core-gmond", rpm:"ganglia-monitor-core-gmond~2.5.7~172.40.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-webfrontend", rpm:"ganglia-webfrontend~2.5.7~172.40.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gdbm", rpm:"gdbm~1.8.3~371.8", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gdbm-devel", rpm:"gdbm-devel~1.8.3~371.8", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"intel-iamt-heci-kmp-debug", rpm:"intel-iamt-heci-kmp-debug~3.1.0.31_2.6.27.23_0.1~2.40.8", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"intel-iamt-heci-kmp-trace", rpm:"intel-iamt-heci-kmp-trace~3.1.0.31_2.6.27.23_0.1~2.40.8", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iscsitarget-kmp-debug", rpm:"iscsitarget-kmp-debug~0.4.15_2.6.27.23_0.1~89.11.12", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iscsitarget-kmp-trace", rpm:"iscsitarget-kmp-trace~0.4.15_2.6.27.23_0.1~89.11.12", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-extra", rpm:"kernel-debug-extra~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~2.6.27.23~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kmp-debug", rpm:"kqemu-kmp-debug~1.4.0pre1_2.6.27.23_0.1~2.1.8", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kmp-trace", rpm:"kqemu-kmp-trace~1.4.0pre1_2.6.27.23_0.1~2.1.8", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kvm-kmp-trace", rpm:"kvm-kmp-trace~78_2.6.27.23_0.1~6.6.20", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8h~28.9.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8h~28.9.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulse-browse0", rpm:"libpulse-browse0~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulse-devel", rpm:"libpulse-devel~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulse-mainloop-glib0", rpm:"libpulse-mainloop-glib0~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulse0", rpm:"libpulse0~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsatsolver-devel", rpm:"libsatsolver-devel~0.13.7~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsnmp15", rpm:"libsnmp15~5.4.2.1~5.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.4.6~11.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.4.6~11.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvirt-doc", rpm:"libvirt-doc~0.4.6~11.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.4.6~11.13.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~5.30.3~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libzypp-devel", rpm:"libzypp-devel~5.30.3~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lirc-kmp-trace", rpm:"lirc-kmp-trace~0.8.4_2.6.27.23_0.1~0.1.10", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.4.2.1~5.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.4.2.1~5.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nfs-client", rpm:"nfs-client~1.1.3~18.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nfs-doc", rpm:"nfs-doc~1.1.3~18.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nfs-kernel-server", rpm:"nfs-kernel-server~1.1.3~18.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ofed-kmp-debug", rpm:"ofed-kmp-debug~1.4_2.6.27.23_0.1~21.15.10", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ofed-kmp-trace", rpm:"ofed-kmp-trace~1.4_2.6.27.23_0.1~21.15.10", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8h~28.9.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8h~28.9.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"optipng", rpm:"optipng~0.6.1~10.4.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"oracleasm-kmp-debug", rpm:"oracleasm-kmp-debug~2.0.5_2.6.27.23_0.1~2.36.10", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"oracleasm-kmp-trace", rpm:"oracleasm-kmp-trace~2.0.5_2.6.27.23_0.1~2.36.10", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pango", rpm:"pango~1.22.1~2.12.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pango-devel", rpm:"pango-devel~1.22.1~2.12.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pango-doc", rpm:"pango-doc~1.22.1~2.12.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pango-module-thai-lang", rpm:"pango-module-thai-lang~1.22.1~2.12.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcfclock-kmp-debug", rpm:"pcfclock-kmp-debug~0.44_2.6.27.23_0.1~227.56.10", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcfclock-kmp-trace", rpm:"pcfclock-kmp-trace~0.44_2.6.27.23_0.1~227.56.10", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.4.2.1~5.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-satsolver", rpm:"perl-satsolver~0.13.7~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio", rpm:"pulseaudio~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-esound-compat", rpm:"pulseaudio-esound-compat~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-lang", rpm:"pulseaudio-lang~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-bluetooth", rpm:"pulseaudio-module-bluetooth~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-gconf", rpm:"pulseaudio-module-gconf~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-jack", rpm:"pulseaudio-module-jack~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-lirc", rpm:"pulseaudio-module-lirc~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-x11", rpm:"pulseaudio-module-x11~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-zeroconf", rpm:"pulseaudio-module-zeroconf~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-utils", rpm:"pulseaudio-utils~0.9.14~2.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-satsolver", rpm:"python-satsolver~0.13.7~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.10~17.30.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"quagga-devel", rpm:"quagga-devel~0.99.10~17.30.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-satsolver", rpm:"ruby-satsolver~0.13.7~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"satsolver-tools", rpm:"satsolver-tools~0.13.7~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.4.2.1~5.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~4.2.8~1.25.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"strongswan-doc", rpm:"strongswan-doc~4.2.8~1.25.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virt-manager", rpm:"virt-manager~0.5.3~64.24.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virt-viewer", rpm:"virt-viewer~0.0.3~3.28.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox-ose-kmp-debug", rpm:"virtualbox-ose-kmp-debug~2.0.6_2.6.27.23_0.1~2.8.32", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox-ose-kmp-trace", rpm:"virtualbox-ose-kmp-trace~2.0.6_2.6.27.23_0.1~2.8.32", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vm-install", rpm:"vm-install~0.3.24~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vmware-kmp-debug", rpm:"vmware-kmp-debug~2008.09.03_2.6.27.23_0.1~5.50.25", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vmware-kmp-trace", rpm:"vmware-kmp-trace~2008.09.03_2.6.27.23_0.1~5.50.25", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.0.4~2.9.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.0.4~2.9.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen", rpm:"xen~3.3.1_18546_16~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.3.1_18546_16~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~3.3.1_18546_16~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~3.3.1_18546_16~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.3.1_18546_16~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~3.3.1_18546_16~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~3.3.1_18546_16~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"RealPlayer", rpm:"RealPlayer~10.0.9~51.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acerhk-kmp-debug", rpm:"acerhk-kmp-debug~0.5.35_2.6.25.20_0.4~98.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.5~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acx-kmp-debug", rpm:"acx-kmp-debug~20080210_2.6.25.20_0.4~3.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"appleir-kmp-debug", rpm:"appleir-kmp-debug~1.1_2.6.25.20_0.4~108.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"at76_usb-kmp-debug", rpm:"at76_usb-kmp-debug~0.17_2.6.25.20_0.4~2.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"atl2-kmp-debug", rpm:"atl2-kmp-debug~2.0.4_2.6.25.20_0.4~4.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"aufs-kmp-debug", rpm:"aufs-kmp-debug~cvs20080429_2.6.25.20_0.4~13.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~140.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-crammd5", rpm:"cyrus-sasl-crammd5~2.1.22~140.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-devel", rpm:"cyrus-sasl-devel~2.1.22~140.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-digestmd5", rpm:"cyrus-sasl-digestmd5~2.1.22~140.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-gssapi", rpm:"cyrus-sasl-gssapi~2.1.22~140.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-ntlm", rpm:"cyrus-sasl-ntlm~2.1.22~140.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-otp", rpm:"cyrus-sasl-otp~2.1.22~140.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-plain", rpm:"cyrus-sasl-plain~2.1.22~140.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dazuko-kmp-debug", rpm:"dazuko-kmp-debug~2.3.4.4_2.6.25.20_0.4~42.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dos2unix", rpm:"dos2unix~3.1~413.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"drbd-kmp-debug", rpm:"drbd-kmp-debug~8.2.6_2.6.25.20_0.4~0.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-monitor-core", rpm:"ganglia-monitor-core~2.5.7~162.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-monitor-core-devel", rpm:"ganglia-monitor-core-devel~2.5.7~162.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-monitor-core-gmetad", rpm:"ganglia-monitor-core-gmetad~2.5.7~162.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-monitor-core-gmond", rpm:"ganglia-monitor-core-gmond~2.5.7~162.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-webfrontend", rpm:"ganglia-webfrontend~2.5.7~162.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gspcav-kmp-debug", rpm:"gspcav-kmp-debug~01.00.20_2.6.25.20_0.4~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iscsitarget-kmp-debug", rpm:"iscsitarget-kmp-debug~0.4.15_2.6.25.20_0.4~63.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ivtv-kmp-debug", rpm:"ivtv-kmp-debug~1.0.3_2.6.25.20_0.4~66.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.25.20~0.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.25.20~0.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.25.20~0.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.25.20~0.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.25.20~0.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.25.20~0.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.25.20~0.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kmp-debug", rpm:"kqemu-kmp-debug~1.3.0pre11_2.6.25.20_0.4~7.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8g~47.6", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8g~47.6", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsnmp15", rpm:"libsnmp15~5.4.1~77.6", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.4.1~77.6", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.4.1~77.6", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nouveau-kmp-debug", rpm:"nouveau-kmp-debug~0.10.1.20081112_2.6.25.20_0.4~0.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"omnibook-kmp-debug", rpm:"omnibook-kmp-debug~20080313_2.6.25.20_0.4~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8g~47.6", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-certs", rpm:"openssl-certs~0.9.8g~47.6", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8g~47.6", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"optipng", rpm:"optipng~0.6.2~2.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcc-acpi-kmp-debug", rpm:"pcc-acpi-kmp-debug~0.9_2.6.25.20_0.4~4.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pcfclock-kmp-debug", rpm:"pcfclock-kmp-debug~0.44_2.6.25.20_0.4~207.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.4.1~77.6", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.9~59.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"quagga-devel", rpm:"quagga-devel~0.99.9~59.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.4.1~77.6", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~4.2.1~11.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"strongswan-doc", rpm:"strongswan-doc~4.2.1~11.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tpctl-kmp-debug", rpm:"tpctl-kmp-debug~4.17_2.6.25.20_0.4~189.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"uvcvideo-kmp-debug", rpm:"uvcvideo-kmp-debug~r200_2.6.25.20_0.4~2.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox-ose-kmp-debug", rpm:"virtualbox-ose-kmp-debug~1.5.6_2.6.25.20_0.4~33.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vmware-kmp-debug", rpm:"vmware-kmp-debug~2008.04.14_2.6.25.20_0.4~21.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.0.0~17.12", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.0.0~17.12", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wlan-ng-kmp-debug", rpm:"wlan-ng-kmp-debug~0.2.8_2.6.25.20_0.4~107.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"RealPlayer", rpm:"RealPlayer~10.0.9~11.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.5~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.2.12~22.24", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~1.2.12~22.24", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.2.12~22.24", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.2.12~22.24", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~82.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-crammd5", rpm:"cyrus-sasl-crammd5~2.1.22~82.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-devel", rpm:"cyrus-sasl-devel~2.1.22~82.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-digestmd5", rpm:"cyrus-sasl-digestmd5~2.1.22~82.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-gssapi", rpm:"cyrus-sasl-gssapi~2.1.22~82.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-otp", rpm:"cyrus-sasl-otp~2.1.22~82.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl-plain", rpm:"cyrus-sasl-plain~2.1.22~82.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dos2unix", rpm:"dos2unix~3.1~376.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-monitor-core", rpm:"ganglia-monitor-core~2.5.7~99.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-monitor-core-devel", rpm:"ganglia-monitor-core-devel~2.5.7~99.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-monitor-core-gmetad", rpm:"ganglia-monitor-core-gmetad~2.5.7~99.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-monitor-core-gmond", rpm:"ganglia-monitor-core-gmond~2.5.7~99.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ganglia-webfrontend", rpm:"ganglia-webfrontend~2.5.7~99.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.22.19~0.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.22.19~0.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.22.19~0.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.22.19~0.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.22.19~0.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.22.19~0.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.22.19~0.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8e~45.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8e~45.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsnmp15", rpm:"libsnmp15~5.4.1~19.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.4.1~19.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.4.1~19.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~45.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-certs", rpm:"openssl-certs~0.9.8e~45.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8e~45.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"optipng", rpm:"optipng~0.6.2~2.3", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.4.1~19.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.7~37.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"quagga-devel", rpm:"quagga-devel~0.99.7~37.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.4.1~19.6", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~0.99.6~31.18", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~0.99.6~31.18", rls:"openSUSE10.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
