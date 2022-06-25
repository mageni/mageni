# OpenVAS Vulnerability Test
# $Id: deb_1503_2.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1503-2 (kernel-source-2.4.27 (2.4.27-10sarge7))
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
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
tag_insight = "Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code.

The package versions referenced in the initial DSA-1503 advisory
introduced a regression that can cause hangs on systems that make use of
the ext2 filesystem. The regression has been resolved in the package
versions referenced by this updated advisory.

For details, please visit the referenced security advisories.

The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update:

Debian 3.1 (sarge)
alsa-modules-i386           1.0.8+2sarge2
fai-kernels                 1.9.1sarge9
kernel-image-2.4.27-arm     2.4.27-2sarge7
kernel-image-2.4.27-m68k    2.4.27-3sarge7
kernel-image-speakup-i386   2.4.27-1.1sarge6
kernel-image-2.4.27-alpha   2.4.27-10sarge7
kernel-image-2.4.27-s390    2.4.27-2sarge7
kernel-image-2.4.27-sparc   2.4.27-9sarge7
kernel-image-2.4.27-i386    2.4.27-10sarge7
kernel-image-2.4.27-ia64    2.4.27-10sarge7
kernel-patch-2.4.27-mips    2.4.27-10.sarge4.040815-4
kernel-patch-powerpc-2.4.27 2.4.27-10sarge7
kernel-latest-2.4-alpha     101sarge3
kernel-latest-2.4-i386      101sarge2
kernel-latest-2.4-s390      2.4.27-1sarge2
kernel-latest-2.4-sparc     42sarge3
i2c                         1:2.9.1-1sarge2
lm-sensors                  1:2.9.1-1sarge4
mindi-kernel                2.4.27-2sarge6
pcmcia-modules-2.4.27-i386  3.2.5+2sarge2
hostap-modules-i386         1:0.3.7-1sarge3
systemimager                3.2.3-6sarge6

We recommend that you upgrade your kernel package immediately and reboot";
tag_summary = "The remote host is missing an update to kernel-source-2.4.27 (2.4.27-10sarge7)
announced via advisory DSA 1503-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201503-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300053");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-03-11 21:16:32 +0100 (Tue, 11 Mar 2008)");
 script_cve_id("CVE-2004-2731", "CVE-2006-4814", "CVE-2006-5753", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6054", "CVE-2006-6106", "CVE-2007-1353", "CVE-2007-1592", "CVE-2007-2172", "CVE-2007-2525", "CVE-2007-3848", "CVE-2007-4308", "CVE-2007-4311", "CVE-2007-5093", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6694", "CVE-2008-0007");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 1503-2 (kernel-source-2.4.27 (2.4.27-10sarge7))");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"systemimager-server-flamethrowerd", ver:"3.2.3-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-boot-i386-standard", ver:"3.2.3-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.4.27", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-server", ver:"3.2.3-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-boot-ia64-standard", ver:"3.2.3-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-debian-2.4.27", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-doc", ver:"3.2.3-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-tree-2.4.27", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-doc-2.4.27", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-client", ver:"3.2.3-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-common", ver:"3.2.3-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-doc-2.4.27-speakup", ver:"2.4.27-1.1sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-source", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4-i2c", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4-lm-sensors", ver:"2.9.1-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-source", ver:"2.9.1-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-generic", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-4", ver:"2.4.27-9sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-generic", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4", ver:"2.4.27-9sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mips-tools", ver:"2.4.27-10.sarge4.040815-4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-generic", ver:"101sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-smp", ver:"101sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-generic", ver:"101sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-smp", ver:"101sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsensors-dev", ver:"2.9.1-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsensors3", ver:"2.9.1-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors", ver:"2.9.1-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sensord", ver:"2.9.1-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27", ver:"2.4.27-10.sarge4.040815-4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27", ver:"2.4.27-2sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-bast", ver:"2.4.27-2sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-riscstation", ver:"2.4.27-2sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-lart", ver:"2.4.27-2sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-riscpc", ver:"2.4.27-2sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-netwinder", ver:"2.4.27-2sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-586tsc", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-386", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-4-686", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-4-586tsc", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-686-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-4-k6", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-686", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-k7", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-4-686-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-686-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-4-386", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-k7", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-speakup", ver:"2.4.27-1.1sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-k6", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fai-kernels", ver:"1.9.1sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-686", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-k7-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-4-k7-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-386", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-k7-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-k6", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-586tsc", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-speakup", ver:"2.4.27-1.1sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-4-k7", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mindi-kernel", ver:"2.4.27-2sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-386", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-586tsc", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-686", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-686-smp", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-k6", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-k7", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4-k7-smp", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-3-386", ver:"1.0.8+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-3-586tsc", ver:"1.0.8+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-3-686", ver:"1.0.8+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-3-686-smp", ver:"1.0.8+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-3-k6", ver:"1.0.8+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-3-k7", ver:"1.0.8+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-3-k7-smp", ver:"1.0.8+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-386", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-586tsc", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-686", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-686-smp", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-k6", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-k7", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-k7-smp", ver:"1.0.8+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-386", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-586tsc", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-686", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-686-smp", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-k6", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-k7", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-k7-smp", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-386", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-586tsc", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-686", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-686-smp", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-k6", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-k7", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-k7-smp", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-386", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-586tsc", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-686", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-686-smp", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-k6", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-k7", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4-k7-smp", ver:"101sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-386", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-586tsc", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-686", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-686-smp", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-k6", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-k7", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-3-k7-smp", ver:"2.9.1-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-4-386", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-4-586tsc", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-4-686", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-4-686-smp", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-4-k6", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-4-k7", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-2.4.27-4-k7-smp", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-2-386", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-2-586tsc", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-2-686", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-2-686-smp", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-2-k6", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-2-k7", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-2-k7-smp", ver:"2.9.1-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-386", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-586tsc", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-686", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-686-smp", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-k6", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-k7", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-3-k7-smp", ver:"2.9.1-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-4-386", ver:"2.9.1-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-4-586tsc", ver:"2.9.1-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-4-686", ver:"2.9.1-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-4-686-smp", ver:"2.9.1-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-4-k6", ver:"2.9.1-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-4-k7", ver:"2.9.1-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lm-sensors-2.4.27-4-k7-smp", ver:"2.9.1-1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-386", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-586tsc", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-686", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-686-smp", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-k6", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-k7", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-3-k7-smp", ver:"3.2.5+2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-4-386", ver:"3.2.5+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-4-586tsc", ver:"3.2.5+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-4-686", ver:"3.2.5+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-4-686-smp", ver:"3.2.5+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-4-k6", ver:"3.2.5+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-4-k7", ver:"3.2.5+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.27-4-k7-smp", ver:"3.2.5+2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-386", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-586tsc", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-686", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-686-smp", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-k6", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-k7", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-k7-smp", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-4-386", ver:"0.3.7-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-4-586tsc", ver:"0.3.7-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-4-686", ver:"0.3.7-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-4-686-smp", ver:"0.3.7-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-4-k6", ver:"0.3.7-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-4-k7", ver:"0.3.7-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-4-k7-smp", ver:"0.3.7-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-3-386", ver:"0.3.7-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-3-686", ver:"0.3.7-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-3-686-smp", ver:"0.3.7-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-3-k7", ver:"0.3.7-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-3-k7-smp", ver:"0.3.7-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-4-386", ver:"0.3.7-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-4-686", ver:"0.3.7-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-4-686-smp", ver:"0.3.7-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-4-k7", ver:"0.3.7-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-4-k7-smp", ver:"0.3.7-1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-mckinley", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-itanium-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-mckinley-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-itanium-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-itanium-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-itanium", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-itanium", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-itanium", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-mckinley-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-mckinley-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-mckinley", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-mckinley", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-mvme16x", ver:"2.4.27-3sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-mac", ver:"2.4.27-3sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-atari", ver:"2.4.27-3sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-mvme147", ver:"2.4.27-3sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-q40", ver:"2.4.27-3sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-amiga", ver:"2.4.27-3sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-bvme6000", ver:"2.4.27-3sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-sb1-swarm-bn", ver:"2.4.27-10.sarge4.040815-4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r5k-ip22", ver:"2.4.27-10.sarge4.040815-4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r4k-ip22", ver:"2.4.27-10.sarge4.040815-4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r5k-cobalt", ver:"2.4.27-10.sarge4.040815-4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r5k-lasat", ver:"2.4.27-10.sarge4.040815-4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-xxs1500", ver:"2.4.27-10.sarge4.040815-4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r3k-kn02", ver:"2.4.27-10.sarge4.040815-4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r4k-kn04", ver:"2.4.27-10.sarge4.040815-4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-powerpc", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-powerpc-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-apus", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-powerpc-small", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-powerpc", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.27-powerpc", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.27-nubus", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-apus", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.27-apus", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-nubus", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-nubus", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-powerpc-smp", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-powerpc", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-powerpc-small", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-apus", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-nubus", ver:"2.4.27-10sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-s390-tape", ver:"2.4.27-2sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-s390x", ver:"2.4.27-2sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-s390", ver:"2.4.27-2sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-s390", ver:"2.4.27-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-s390", ver:"2.4.27-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-s390x", ver:"2.4.27-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-sparc32", ver:"2.4.27-9sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-sparc32", ver:"2.4.27-9sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-sparc64", ver:"2.4.27-9sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-sparc32-smp", ver:"2.4.27-9sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-sparc64-smp", ver:"2.4.27-9sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-sparc32-smp", ver:"2.4.27-9sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-4-sparc64-smp", ver:"2.4.27-9sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-4-sparc64", ver:"2.4.27-9sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-sparc32", ver:"42sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-sparc32-smp", ver:"42sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-sparc64", ver:"42sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4-sparc64-smp", ver:"42sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-sparc32", ver:"42sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-sparc32-smp", ver:"42sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-sparc64", ver:"42sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-sparc64-smp", ver:"42sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
