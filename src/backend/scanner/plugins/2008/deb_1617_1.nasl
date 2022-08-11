# OpenVAS Vulnerability Test
# $Id: deb_1617_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1617-1 (refpolicy)
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
tag_insight = "In DSA-1603-1, Debian released an update to the BIND 9 domain name
server, which introduced UDP source port randomization to mitigate
the threat of DNS cache poisoning attacks (identified by the Common
Vulnerabilities and Exposures project as CVE-2008-1447).  The fix,
while correct, was incompatible with the version of SELinux Reference
Policy shipped with Debian Etch, which did not permit a process
running in the named_t domain to bind sockets to UDP ports other than
the standard 'domain' port (53).  The incompatibility affects both
the 'targeted' and 'strict' policy packages supplied by this version
of refpolicy.

This update to the refpolicy packages grants the ability to bind to
arbitrary UDP ports to named_t processes.  When installed, the
updated packages will attempt to update the bind policy module on
systems where it had been previously loaded and where the previous
version of refpolicy was 0.0.20061018-5 or below.

Because the Debian refpolicy packages are not yet designed with
policy module upgradeability in mind, and because SELinux-enabled
Debian systems often have some degree of site-specific policy
customization, it is difficult to assure that the new bind policy can
be successfully upgraded.  To this end, the package upgrade will not
abort if the bind policy update fails.  The new policy module can be
found at /usr/share/selinux/refpolicy-targeted/bind.pp after
installation.  Administrators wishing to use the bind service policy
can reconcile any policy incompatibilities and install the upgrade
manually thereafter.  A more detailed discussion of the corrective
procedure may be found here:

http://wiki.debian.org/SELinux/Issues/BindPortRandomization

For the stable distribution (etch), this problem has been fixed in
version 0.0.20061018-5.1+etch1.  The unstable distribution (sid) is
not affected, as subsequent refpolicy releases have incorporated an
analogous change.

We recommend that you upgrade your refpolicy packages.";
tag_summary = "The remote host is missing an update to refpolicy
announced via advisory DSA 1617-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201617-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301675");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-08-15 15:52:52 +0200 (Fri, 15 Aug 2008)");
 script_cve_id("CVE-2008-1447");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 1617-1 (refpolicy)");



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
if ((res = isdpkgvuln(pkg:"selinux-policy-refpolicy-strict", ver:"0.0.20061018-5.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"selinux-policy-refpolicy-doc", ver:"0.0.20061018-5.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"selinux-policy-refpolicy-targeted", ver:"0.0.20061018-5.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"selinux-policy-refpolicy-src", ver:"0.0.20061018-5.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"selinux-policy-refpolicy-dev", ver:"0.0.20061018-5.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
