# OpenVAS Vulnerability Test
# $Id: RHSA_2008_0002.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2008:0002 ()
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
tag_insight = "The tog-pegasus packages provide OpenPegasus Web-Based Enterprise
Management (WBEM) services. WBEM is a platform and resource independent
DMTF standard that defines a common information model, and communication
protocol for monitoring and controlling resources.

During a security audit, a stack buffer overflow flaw was found in the PAM
authentication code in the OpenPegasus CIM management server. An
unauthenticated remote user could trigger this flaw and potentially execute
arbitrary code with root privileges. (CVE-2008-0003)

Note that the tog-pegasus packages are not installed by default on Red Hat
Enterprise Linux. The Red Hat Security Response Team believes that it would
be hard to remotely exploit this issue to execute arbitrary code, due to
the default SELinux targeted policy on Red Hat Enterprise Linux 4 and 5,
and the SELinux memory protection tests enabled by default on Red Hat
Enterprise Linux 5.

Users of tog-pegasus should upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
updated packages the tog-pegasus service should be restarted.";
tag_summary = "The remote host is missing updates announced in
advisory RHSA-2008:0002.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date

http://rhn.redhat.com/errata/RHSA-2008-0002.html
http://www.redhat.com/security/updates/classification/#critical";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307232");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-09 19:38:29 +0200 (Tue, 09 Jun 2009)");
 script_cve_id("CVE-2008-0003");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("RedHat Security Advisory RHSA-2008:0002");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"tog-pegasus", rpm:"tog-pegasus~2.5.1~5.el4_6.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-debuginfo", rpm:"tog-pegasus-debuginfo~2.5.1~5.el4_6.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-devel", rpm:"tog-pegasus-devel~2.5.1~5.el4_6.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-test", rpm:"tog-pegasus-test~2.5.1~5.el4_6.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus", rpm:"tog-pegasus~2.5.1~2.el4_5.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-debuginfo", rpm:"tog-pegasus-debuginfo~2.5.1~2.el4_5.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-devel", rpm:"tog-pegasus-devel~2.5.1~2.el4_5.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-test", rpm:"tog-pegasus-test~2.5.1~2.el4_5.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus", rpm:"tog-pegasus~2.6.1~2.el5_1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-debuginfo", rpm:"tog-pegasus-debuginfo~2.6.1~2.el5_1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-devel", rpm:"tog-pegasus-devel~2.6.1~2.el5_1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
