# OpenVAS Vulnerability Test
# $Id: RHSA_2009_0297.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:0297 ()
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
advisory RHSA-2009:0297.

In accordance with the Red Hat Enterprise Linux Errata Support Policy, the
7 years life-cycle of Red Hat Enterprise Linux 2.1 will end on May 31 2009.

After that date, Red Hat will discontinue the technical support services,
bugfix, enhancement and security errata updates for the following products:

* Red Hat Enterprise Linux AS 2.1
* Red Hat Enterprise Linux ES 2.1
* Red Hat Enterprise Linux WS 2.1
* Red Hat Linux Advanced Server 2.1
* Red Hat Linux Advanced Workstation 2.1

Customers running production workloads on Enterprise Linux 2.1 should plan
to migrate to a later version before May 31, 2009.  One benefit of a Red
Hat subscription is the right to upgrade to never versions of Enterprise
Linux for no extra cost. As an Enterprise Linux subscriber, you have the
option of migrating to the following supported versions:

* version 3 (Generally Available: Oct 2003, End-Of-Life: Oct 2010)
* version 4 (GA: Feb 2005, EOL: Feb 2012)
* version 5 (GA: Mar 2007, EOL: Mar 2014)

These supported versions of Enterprise Linux are available for download
from Red Hat Network.

For those customers who cannot migrate from Enterprise Linux 2.1 before its
end-of-life date, Red Hat will offer limited extended support contracts.
For more information, contact your Red Hat sales representative.

Details of the Red Hat Enterprise Linux life-cycle can be found on the Red
Hat website: http://www.redhat.com/security/updates/errata/";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310157");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-03-07 21:47:03 +0100 (Sat, 07 Mar 2009)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("RedHat Security Advisory RHSA-2009:0297");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-0297.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/errata/");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"redhat-release-as", rpm:"redhat-release-as~2.1AS~24", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"redhat-release-as", rpm:"redhat-release-as~2.1AS~124", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"redhat-release-aw", rpm:"redhat-release-aw~2.1AW~24", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"redhat-release-es", rpm:"redhat-release-es~2.1ES~24", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"redhat-release-ws", rpm:"redhat-release-ws~2.1WS~24", rls:"RHENT_2.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
