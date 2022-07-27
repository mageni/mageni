# OpenVAS Vulnerability Test
# $Id: deb_1018_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1018-1
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
tag_insight = "The following matrix explains which kernel version for which architecture
fix the problems addressed with this update:

Debian 3.1 (sarge)
Source                          2.4.27-10sarge2
Alpha architecture              2.4.27-10sarge2
ARM architecture                2.4.27-2sarge2
Intel IA-32 architecture        2.4.27-10sarge2
Intel IA-64 architecture        2.4.27-10sarge2
Motorola 680x0 architecture     2.4.27-3sarge2
Big endian MIPS architecture    2.4.27-10.sarge1.040815-2
Little endian MIPS architecture 2.4.27-10.sarge1.040815-2
PowerPC architecture            2.4.27-10sarge2
IBM S/390 architecture          2.4.27-2sarge2
Sun Sparc architecture          2.4.27-9sarge2

The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update:

Debian 3.1 (sarge)
kernel-latest-2.4-alpha         101sarge1
kernel-latest-2.4-i386          101sarge1
kernel-latest-2.4-s390          2.4.27-1sarge1
kernel-latest-2.4-sparc         42sarge1
kernel-latest-powerpc           102sarge1
fai-kernels                     1.9.1sarge1
i2c                             1:2.9.1-1sarge1
kernel-image-speakup-i386       2.4.27-1.1sasrge1
lm-sensors                      1:2.9.1-1sarge3
mindi-kernel                    2.4.27-2sarge1
pcmcia-modules-2.4.27-i386      3.2.5+2sarge1
systemimager                    3.2.3-6sarge1

We recommend that you upgrade your kernel package immediately and reboot";
tag_summary = "The remote host is missing an update to kernel-source-2.4.27
announced via advisory DSA 1018-1. For details on the issues
addressed with this update, please visit the referenced
security advisories.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201018-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302620");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:09:45 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0887", "CVE-2004-1058", "CVE-2004-2607", "CVE-2005-0449", "CVE-2005-1761", "CVE-2005-2457", "CVE-2005-2555", "CVE-2005-2709", "CVE-2005-2973", "CVE-2005-3257", "CVE-2005-3783", "CVE-2005-3806", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858", "CVE-2005-4618");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 1018-1 (kernel-source-2.4.27)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"kernel-patch-debian-2.4.27", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-source", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-doc-2.4.27-speakup", ver:"2.4.27-1.1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-boot-ia64-standard", ver:"3.2.3-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-boot-i386-standard", ver:"3.2.3-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-source", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-doc-2.4.27", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-tree-2.4.27", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-common", ver:"3.2.3-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-doc", ver:"3.2.3-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4-i2c", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-server", ver:"3.2.3-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.4.27", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-client", ver:"3.2.3-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-server-flamethrowerd", ver:"3.2.3-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4-lm-sensors", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3", ver:"2.4.27-9sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-smp", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-generic", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-generic", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-generic", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-generic", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-3", ver:"2.4.27-9sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-smp", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27", ver:"2.4.27-10.sarge2.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-riscpc", ver:"2.4.27-2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-riscstation", ver:"2.4.27-2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-netwinder", ver:"2.4.27-2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-lart", ver:"2.4.27-2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27", ver:"2.4.27-2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-bast", ver:"2.4.27-2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-speakup", ver:"2.4.27-1.1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-686", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-686-smp", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-k6", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-k6", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-586tsc", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-k7", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-386", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-k7-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-386", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-586tsc", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-386", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-686-smp", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-586tsc", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-686-smp", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-386", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-586tsc", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-k7", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-386", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-686", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-386", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-686", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-586tsc", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mindi-kernel", ver:"2.4.27-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-386", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-386", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-k7-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-k7-smp", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-586tsc", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-k7-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-k7", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-686", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-k6", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-586tsc", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-k7-smp", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-686", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-586tsc", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-k6", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-686", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-386", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-686", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-686-smp", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-k7-smp", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-686-smp", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsensors-dev", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-k6", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-k7-smp", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-k6", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-k7", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-586tsc", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-686-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-686", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sensord", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-k6", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-686-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-speakup", ver:"2.4.27-1.1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-686-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-k7", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-k6", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-k6", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-686", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-686-smp", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-k7-smp", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-k7", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-k7", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-k7", ver:"101sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-k7-smp", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-k7", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsensors3", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-mckinley-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-itanium-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-mckinley", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-itanium-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-mckinley-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-itanium", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-itanium", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-mckinley-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-itanium-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-mckinley", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-mckinley", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-itanium", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-mvme147", ver:"2.4.27-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-amiga", ver:"2.4.27-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-mvme16x", ver:"2.4.27-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-bvme6000", ver:"2.4.27-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-q40", ver:"2.4.27-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-atari", ver:"2.4.27-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-mac", ver:"2.4.27-3sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r5k-ip22", ver:"2.4.27-10.sarge2.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r4k-ip22", ver:"2.4.27-10.sarge2.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-sb1-swarm-bn", ver:"2.4.27-10.sarge2.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mips-tools", ver:"2.4.27-10.sarge2.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r5k-lasat", ver:"2.4.27-10.sarge2.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r5k-cobalt", ver:"2.4.27-10.sarge2.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-xxs1500", ver:"2.4.27-10.sarge2.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r4k-kn04", ver:"2.4.27-10.sarge2.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r3k-kn02", ver:"2.4.27-10.sarge2.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.27-powerpc", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-powerpc", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-nubus", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-powerpc-small", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.27-nubus", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.27-apus", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-apus", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-powerpc-small", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-powerpc", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-apus", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-powerpc", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-nubus", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-powerpc-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-apus", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-powerpc-smp", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-nubus", ver:"2.4.27-10sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-s390x", ver:"2.4.27-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-s390", ver:"2.4.27-2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-s390", ver:"2.4.27-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-s390x", ver:"2.4.27-2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-s390", ver:"2.4.27-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-s390-tape", ver:"2.4.27-2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-sparc32", ver:"42sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-sparc32-smp", ver:"2.4.27-9sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-sparc64-smp", ver:"42sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-sparc32", ver:"2.4.27-9sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-sparc64-smp", ver:"2.4.27-9sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-sparc32", ver:"2.4.27-9sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-sparc64", ver:"2.4.27-9sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-sparc32-smp", ver:"42sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-sparc32-smp", ver:"42sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-sparc64", ver:"2.4.27-9sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-sparc64-smp", ver:"2.4.27-9sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-sparc64", ver:"42sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-sparc64", ver:"42sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-sparc32-smp", ver:"2.4.27-9sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-sparc32", ver:"42sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-sparc64-smp", ver:"42sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
