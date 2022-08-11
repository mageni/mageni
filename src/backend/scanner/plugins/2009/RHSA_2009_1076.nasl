# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1076.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:1076 ()
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
advisory RHSA-2009:1076.

In accordance with the Red Hat Enterprise Linux Errata Support Policy, the
7 year life-cycle of Red Hat Enterprise Linux 2.1 has ended.

Red Hat has discontinued the technical support services, bug fix,
enhancement, and security errata updates for the following versions:

* Red Hat Enterprise Linux AS 2.1
* Red Hat Enterprise Linux ES 2.1
* Red Hat Enterprise Linux WS 2.1
* Red Hat Linux Advanced Server 2.1
* Red Hat Linux Advanced Workstation 2.1

Servers subscribed to Red Hat Enterprise Linux 2.1 channels on the Red Hat
Network will become unsubscribed. As a benefit of the Red Hat subscription
model, those subscriptions can be used to entitle any system on any
currently supported release of Red Hat Enterprise Linux. Details of the Red
Hat Enterprise Linux life-cycle for all releases can be found on the Red
Hat website:


As part of the End Of Life process, the Red Hat Network will cease to carry
the Red Hat Enterprise Linux 2.1 binaries. The source code and security
advisories will continue to be available.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311877");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("RedHat Security Advisory RHSA-2009:1076");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/errata/");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1076.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#low");

 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"redhat-release-as", rpm:"redhat-release-as~2.1AS~25", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"redhat-release-as", rpm:"redhat-release-as~2.1AS~125", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"redhat-release-aw", rpm:"redhat-release-aw~2.1AW~25", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"redhat-release-es", rpm:"redhat-release-es~2.1ES~25", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"redhat-release-ws", rpm:"redhat-release-ws~2.1WS~25", rls:"RHENT_2.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
