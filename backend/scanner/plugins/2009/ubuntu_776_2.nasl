# OpenVAS Vulnerability Test
# $Id: ubuntu_776_2.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_776_2.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-776-2 (kvm)
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

Ubuntu 8.04 LTS:
  kvm                             1:62+dfsg-0ubuntu8.2

After a standard system upgrade you need to restart all KVM VMs to effect
the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-776-2";

tag_insight = "USN-776-1 fixed vulnerabilities in KVM. Due to an incorrect fix, a
regression was introduced in Ubuntu 8.04 LTS that caused KVM to fail to
boot virtual machines started via libvirt. This update fixes the problem.
We apologize for the inconvenience.

Original advisory details:

 Avi Kivity discovered that KVM did not correctly handle certain disk
 formats. A local attacker could attach a malicious partition that would
 allow the guest VM to read files on the VM host. (CVE-2008-1945,
 CVE-2008-2004)

 Alfredo Ortega discovered that KVM's VNC protocol handler did not
 correctly validate certain messages. A remote attacker could send
 specially crafted VNC messages that would cause KVM to consume CPU
 resources, leading to a denial of service. (CVE-2008-2382)

 Jan Niehusmann discovered that KVM's Cirrus VGA implementation over VNC
 did not correctly handle certain bitblt operations. A local attacker could
 exploit this flaw to potentially execute arbitrary code on the VM host or
 crash KVM, leading to a denial of service. (CVE-2008-4539)

 It was discovered that KVM's VNC password checks did not use the correct
 length. A remote attacker could exploit this flaw to cause KVM to crash,
 leading to a denial of service. (CVE-2008-5714)";
tag_summary = "The remote host is missing an update to kvm
announced via advisory USN-776-2.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305204");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
 script_cve_id("CVE-2008-1945", "CVE-2008-2004", "CVE-2008-2382", "CVE-2008-4539", "CVE-2008-5714", "CVE-2009-1130", "CVE-2009-1574", "CVE-2009-0714", "CVE-2008-1517", "CVE-2007-2807", "CVE-2009-0159", "CVE-2009-1252", "CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1580", "CVE-2009-1581", "CVE-2009-1418", "CVE-2009-0028", "CVE-2009-0269", "CVE-2009-0342", "CVE-2009-0343", "CVE-2009-0834", "CVE-2009-0835", "CVE-2009-1184", "CVE-2009-1415", "CVE-2009-1416", "CVE-2009-1417", "CVE-2009-0154", "CVE-2009-1150", "CVE-2009-1151", "CVE-2009-0922", "CVE-2009-1632", "CVE-2009-0945", "CVE-2009-0688", "CVE-2009-1527", "CVE-2009-1338", "CVE-2009-1242", "CVE-2009-1192", "CVE-2009-1439", "CVE-2009-1337", "CVE-2009-0157", "CVE-2008-5077", "CVE-2008-5814", "CVE-2009-0721", "CVE-2009-0859", "CVE-2009-1046", "CVE-2009-1072", "CVE-2009-1265", "CVE-2009-1011", "CVE-2009-1010", "CVE-2009-1009", "CVE-2009-1161");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-776-2 (kvm)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-776-2/");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
 script_tag(name : "insight" , value : tag_insight);
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
if ((res = isdpkgvuln(pkg:"kvm-source", ver:"62+dfsg-0ubuntu8.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kvm", ver:"62+dfsg-0ubuntu8.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-refclock", ver:"4.2.2.p4+dfsg-2etch3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.4p4+dfsg-3ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-simple", ver:"4.2.2.p4+dfsg-2etch3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.4p4+dfsg-3ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.4p4+dfsg-3ubuntu2.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squirrelmail", ver:"1.4.15-4+lenny1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-2.6.26-2", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-manual-2.6.26", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-tree-2.6.26", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-2.6.26", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-patch-debian-2.6.26", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-doc-2.6.26", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-alpha-legacy", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-alpha-legacy", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-alpha-generic", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-alpha-smp", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-alpha", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-alpha-smp", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-amd64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common-xen", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-amd64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-amd64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common-openvz", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-xen-amd64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.26-2-xen-amd64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.26-2-xen-amd64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-openvz-amd64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-amd64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common-vserver", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-amd64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-openvz-amd64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-xen-amd64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"user-mode-linux", ver:"2.6.26-1um-2+15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-orion5x", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-ixp4xx", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-footbridge", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-orion5x", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-footbridge", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-ixp4xx", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-iop32x", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-arm", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-iop32x", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-versatile", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-armel", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-versatile", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-parisc64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-parisc64-smp", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-parisc64-smp", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-hppa", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-parisc64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-parisc", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-parisc-smp", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-parisc-smp", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-parisc", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-openvz-686", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-686-bigmem", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-xen-686", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-686", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.26-2-xen-686", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-686-bigmem", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-486", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-686-bigmem", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-686", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-686", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-686-bigmem", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-openvz-686", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.26-2-xen-686", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-xen-686", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-i386", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-686", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-486", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-mckinley", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-mckinley", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-mckinley", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-mckinley", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-itanium", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-ia64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-itanium", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-itanium", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-itanium", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-5kc-malta", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sb1-bcm91250a", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sb1-bcm91250a", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-4kc-malta", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-r4k-ip22", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-mips", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-r5k-ip32", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-5kc-malta", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-r4k-ip22", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-r5k-ip32", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-4kc-malta", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-mipsel", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-r5k-cobalt", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-r5k-cobalt", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-powerpc", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-powerpc64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-powerpc64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-powerpc64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-powerpc", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-powerpc", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-powerpc", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-powerpc-smp", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-powerpc", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-powerpc64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-powerpc-smp", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-s390x", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-s390x", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-s390x", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-s390", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-s390", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-s390-tape", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-s390x", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-s390", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-sparc", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-sparc64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sparc64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sparc64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-sparc64", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sparc64-smp", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sparc64-smp", ver:"2.6.26-15lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nsd", ver:"2.3.7-1.1+lenny1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nsd3", ver:"3.0.7-3.lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"racoon", ver:"0.7.1-1.3+lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipsec-tools", ver:"0.7.1-1.3+lenny2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.0a+stable-8.1ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-server", ver:"4.2.0a+stable-8.1ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-simple", ver:"4.2.0a+stable-8.1ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.0a+stable-8.1ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.0a+stable-8.1ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-refclock", ver:"4.2.0a+stable-8.1ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.4p4+dfsg-6ubuntu2.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.4p4+dfsg-6ubuntu2.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.4p4+dfsg-6ubuntu2.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp-doc", ver:"4.2.4p4+dfsg-7ubuntu5.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntp", ver:"4.2.4p4+dfsg-7ubuntu5.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntpdate", ver:"4.2.4p4+dfsg-7ubuntu5.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
