# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
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
tag_insight = "VMware guest operating systems might be able to execute arbitrary code with
elevated privileges on the host operating system through multiple flaws.";
tag_solution = "All VMware Workstation users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=app-emulation/vmware-workstation-5.5.5.56455'

All VMware Player users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=app-emulation/vmware-player-1.0.5.56455'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200711-23
http://bugs.gentoo.org/show_bug.cgi?id=193196
http://www.gentoo.org/security/en/glsa/glsa-200606-02.xml
http://www.gentoo.org/security/en/glsa/glsa-200702-06.xml
http://www.gentoo.org/security/en/glsa/glsa-200704-11.xml
http://www.gentoo.org/security/en/glsa/glsa-200705-15.xml
http://www.gentoo.org/security/en/glsa/glsa-200707-11.xml
http://lists.vmware.com/pipermail/security-announce/2007/000001.html";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200711-23.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304030");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2004-0813", "CVE-2006-3619", "CVE-2006-4146", "CVE-2006-4600", "CVE-2007-0061", "CVE-2007-0062", "CVE-2007-0063", "CVE-2007-1716", "CVE-2007-4496", "CVE-2007-4497", "CVE-2007-5617");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Gentoo Security Advisory GLSA 200711-23 (vmware-workstation vmware-player)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
 script_family("Gentoo Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
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

include("pkg-lib-gentoo.inc");

res = "";
report = "";
if ((res = ispkgvuln(pkg:"app-emulation/vmware-workstation", unaffected: make_list("rge 5.5.5.56455", "ge 6.0.1.55017"), vulnerable: make_list("lt 6.0.1.55017"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-emulation/vmware-player", unaffected: make_list("rge 1.0.5.56455", "ge 2.0.1.55017"), vulnerable: make_list("lt 2.0.1.55017"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
