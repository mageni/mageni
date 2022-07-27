# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1188.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:1188 ()
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
advisory RHSA-2009:1188.

The flash-plugin package contains a Mozilla Firefox compatible Adobe Flash
Player web browser plug-in.

Multiple security flaws were found in the way Flash Player displayed
certain SWF content. An attacker could use these flaws to create a
specially-crafted SWF file that would cause flash-plugin to crash or,
possibly, execute arbitrary code when the victim loaded a page containing
the specially-crafted SWF content. (CVE-2009-1862, CVE-2009-1863,
CVE-2009-1864, CVE-2009-1865, CVE-2009-1866, CVE-2009-1868, CVE-2009-1869)

A clickjacking flaw was discovered in Flash Player. A specially-crafted
SWF file could trick a user into unintentionally or mistakenly clicking a
link or a dialog. (CVE-2009-1867)

A flaw was found in the Flash Player local sandbox. A specially-crafted
SWF file could cause information disclosure when it was saved to the hard
drive. (CVE-2009-1870)

All users of Adobe Flash Player should install this updated package, which
upgrades Flash Player to version 10.0.32.18.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310458");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_cve_id("CVE-2009-1862", "CVE-2009-1863", "CVE-2009-1864", "CVE-2009-1865", "CVE-2009-1866", "CVE-2009-1867", "CVE-2009-1868", "CVE-2009-1869", "CVE-2009-1870");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("RedHat Security Advisory RHSA-2009:1188");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1188.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#critical");
 script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-10.html");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"flash-plugin", rpm:"flash-plugin~10.0.32.18~2.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
