# OpenVAS Vulnerability Test
# $Id: ubuntu_752_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_752_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-752-1 (linux-source-2.6.15)
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
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  linux-image-2.6.15-54-386       2.6.15-54.76
  linux-image-2.6.15-54-686       2.6.15-54.76
  linux-image-2.6.15-54-amd64-generic  2.6.15-54.76
  linux-image-2.6.15-54-amd64-k8  2.6.15-54.76
  linux-image-2.6.15-54-amd64-server  2.6.15-54.76
  linux-image-2.6.15-54-amd64-xeon  2.6.15-54.76
  linux-image-2.6.15-54-hppa32    2.6.15-54.76
  linux-image-2.6.15-54-hppa32-smp  2.6.15-54.76
  linux-image-2.6.15-54-hppa64    2.6.15-54.76
  linux-image-2.6.15-54-hppa64-smp  2.6.15-54.76
  linux-image-2.6.15-54-itanium   2.6.15-54.76
  linux-image-2.6.15-54-itanium-smp  2.6.15-54.76
  linux-image-2.6.15-54-k7        2.6.15-54.76
  linux-image-2.6.15-54-mckinley  2.6.15-54.76
  linux-image-2.6.15-54-mckinley-smp  2.6.15-54.76
  linux-image-2.6.15-54-powerpc   2.6.15-54.76
  linux-image-2.6.15-54-powerpc-smp  2.6.15-54.76
  linux-image-2.6.15-54-powerpc64-smp  2.6.15-54.76
  linux-image-2.6.15-54-server    2.6.15-54.76
  linux-image-2.6.15-54-server-bigiron  2.6.15-54.76
  linux-image-2.6.15-54-sparc64   2.6.15-54.76
  linux-image-2.6.15-54-sparc64-smp  2.6.15-54.76

After a standard system upgrade you need to reboot your computer to
effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-752-1";

tag_summary = "The remote host is missing an update to linux-source-2.6.15
announced via advisory USN-752-1.

ATTENTION: Due to an unavoidable ABI change the kernel updates have
been given a new version number, which requires you to recompile and
reinstall all third party kernel modules you might have installed. If
you use linux-restricted-modules, you have to update that package as
well to get modules which work with the new kernel version. Unless you
manually uninstalled the standard kernel metapackages (e.g. linux-generic,
linux-server, linux-powerpc), a standard system upgrade will automatically
perform this as well.

For details on the issues addressed in this update, please visit
the referenced security advisories.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305249");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
 script_cve_id("CVE-2008-4307", "CVE-2008-6107", "CVE-2009-0028", "CVE-2009-0029", "CVE-2009-0065", "CVE-2009-0322", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0834", "CVE-2009-0835", "CVE-2009-0859");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-752-1 (linux-source-2.6.15)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-752-1/");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-doc-2.6.15", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-2.6.15", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-common", ver:"2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-amd64-generic", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-amd64-k8", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-amd64-server", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-amd64-xeon", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-amd64-generic", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-amd64-k8", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-amd64-server", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-amd64-xeon", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-amd64-generic", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-amd64-k8", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-amd64-server", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-amd64-xeon", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-amd64-generic", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-amd64-k8", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-amd64-server", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-amd64-xeon", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-amd64-generic", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-amd64-k8", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-amd64-server", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-amd64-xeon", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-amd64-generic", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-amd64-k8", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-amd64-server", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-amd64-xeon", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avm-fritz-kernel-source", ver:"3.11+2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fglrx-kernel-source", ver:"8.25.18+2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nvidia-kernel-source", ver:"1.0.8776+2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nvidia-legacy-kernel-source", ver:"1.0.7174+2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avm-fritz-firmware", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-amd64-generic", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-amd64-k8-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-amd64-k8", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-amd64-server", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-amd64-xeon", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-amd64-generic", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-amd64-k8", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-amd64-xeon", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avm-fritz-firmware-2.6.15-54", ver:"3.11+2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fglrx-control", ver:"8.25.18+2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-54-amd64-generic", ver:"2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-54-amd64-k8", ver:"2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-54-amd64-xeon", ver:"2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nvidia-glx-dev", ver:"1.0.8776+2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nvidia-glx-legacy-dev", ver:"1.0.7174+2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nvidia-glx-legacy", ver:"1.0.7174+2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nvidia-glx", ver:"1.0.8776+2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xorg-driver-fglrx-dev", ver:"7.0.0-8.25.18+2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xorg-driver-fglrx", ver:"7.0.0-8.25.18+2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-386", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-686", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-k7", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-server-bigiron", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-server", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-386", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-686", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-k7", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-server-bigiron", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-server", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-386", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-686", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-k7", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-server-bigiron", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-server", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-386", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-686", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-k7", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-server-bigiron", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-server", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-386", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-686", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-k7", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-server-bigiron", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-server", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-386", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-686", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-k7", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-server-bigiron", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-server", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-386", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-686-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-686", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-k7-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-k7", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-386", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-686", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-k7", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-server-bigiron", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-server", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-54-386", ver:"2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-54-686", ver:"2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-54-k7", ver:"2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-powerpc-smp", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-powerpc64-smp", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-powerpc", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-powerpc-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-powerpc64-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-powerpc", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-power3-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-power3", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-power4-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-power4", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-powerpc-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-powerpc64-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-powerpc", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-power3-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-power3", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-power4-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-power4", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-powerpc", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-powerpc-smp", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-powerpc64-smp", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-powerpc", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-powerpc-smp", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-powerpc64-smp", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-powerpc", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-power3-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-power3", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-power4-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-power4", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-powerpc-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-powerpc64-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-powerpc", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-powerpc-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-powerpc", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-54-powerpc-smp", ver:"2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-54-powerpc", ver:"2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-sparc64-smp", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-2.6.15-54-sparc64", ver:"2.6.15-54.12", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-sparc64-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-backports-modules-sparc64", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-sparc64-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-sparc64", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-sparc64-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-sparc64", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-sparc64-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-sparc64", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-sparc64-smp", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-54-sparc64", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-sparc64-smp", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-54-sparc64", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-sparc64-smp", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-sparc64", ver:"2.6.15.55", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-54-sparc64-smp", ver:"2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-54-sparc64", ver:"2.6.15.12-54.5", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
