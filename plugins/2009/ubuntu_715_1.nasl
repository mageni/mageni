# OpenVAS Vulnerability Test
# $Id: ubuntu_715_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_715_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-715-1 (linux)
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

Ubuntu 8.10:
  linux-image-2.6.27-11-generic   2.6.27-11.27
  linux-image-2.6.27-11-server    2.6.27-11.27
  linux-image-2.6.27-11-virtual   2.6.27-11.27

After a standard system upgrade you need to reboot your computer to
effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-715-1";

tag_insight = "Hugo Dias discovered that the ATM subsystem did not correctly manage
socket counts. A local attacker could exploit this to cause a system hang,
leading to a denial of service. (CVE-2008-5079)

It was discovered that the inotify subsystem contained watch removal
race conditions. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2008-5182)

Dann Frazier discovered that in certain situations sendmsg did not
correctly release allocated memory. A local attacker could exploit
this to force the system to run out of free memory, leading to a denial
of service.  (CVE-2008-5300)

Helge Deller discovered that PA-RISC stack unwinding was not handled
correctly. A local attacker could exploit this to crash the system,
leading do a denial of service. This did not affect official Ubuntu
kernels, but was fixed in the source for anyone performing HPPA kernel
builds.  (CVE-2008-5395)

It was discovered that the ATA subsystem did not correctly set timeouts. A
local attacker could exploit this to cause a system hang, leading to a
denial of service. (CVE-2008-5700)

It was discovered that the ib700 watchdog timer did not correctly check
buffer sizes. A local attacker could send a specially crafted ioctl
to the device to cause a system crash, leading to a denial of service.
(CVE-2008-5702)";
tag_summary = "The remote host is missing an update to linux
announced via advisory USN-715-1.

ATTENTION: Due to an unavoidable ABI change the kernel updates have
been given a new version number, which requires you to recompile and
reinstall all third party kernel modules you might have installed. If
you use linux-restricted-modules, you have to update that package as
well to get modules which work with the new kernel version. Unless you
manually uninstalled the standard kernel metapackages (e.g. linux-generic,
linux-server, linux-powerpc), a standard system upgrade will automatically
perform this as well.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309519");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-02-02 23:28:24 +0100 (Mon, 02 Feb 2009)");
 script_cve_id("CVE-2008-5079", "CVE-2008-5182", "CVE-2008-5300", "CVE-2008-5395", "CVE-2008-5700", "CVE-2008-5702");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-715-1 (linux)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-715-1/");

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
if ((res = isdpkgvuln(pkg:"linux-doc-2.6.27", ver:"2.6.27-11.27", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.27-11", ver:"2.6.27-11.27", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-2.6.27", ver:"2.6.27-11.27", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.27-11-generic", ver:"2.6.27-11.27", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.27-11-server", ver:"2.6.27-11.27", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.27-11-generic", ver:"2.6.27-11.27", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.27-11-server", ver:"2.6.27-11.27", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.27-11-virtual", ver:"2.6.27-11.27", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.27-11.27", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
