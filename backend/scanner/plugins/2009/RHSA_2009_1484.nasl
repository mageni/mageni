# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1484.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:1484 ()
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
tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date

http://rhn.redhat.com/errata/RHSA-2009-1484.html
http://www.redhat.com/security/updates/classification/#moderate";

tag_summary = "The remote host is missing updates announced in
advisory RHSA-2009:1484.

PostgreSQL is an advanced object-relational database management system
(DBMS).

It was discovered that the upstream patch for CVE-2007-6600 included in the
Red Hat Security Advisory RHSA-2008:0038 did not include protection against
misuse of the RESET ROLE and RESET SESSION AUTHORIZATION commands. An
authenticated user could use this flaw to install malicious code that would
later execute with superuser privileges. (CVE-2009-3230)

A flaw was found in the way PostgreSQL handled encoding conversion. A
remote, authenticated user could trigger an encoding conversion failure,
possibly leading to a temporary denial of service. Note: To exploit this
issue, a locale and client encoding for which specific messages fail to
translate must be selected (the availability of these is determined by an
administrator-defined locale setting). (CVE-2009-0922)

Note: For Red Hat Enterprise Linux 4, this update upgrades PostgreSQL to
version 7.4.26. For Red Hat Enterprise Linux 5, this update upgrades
PostgreSQL to version 8.1.18. Refer to the PostgreSQL Release Notes for a
list of changes:


All PostgreSQL users should upgrade to these updated packages, which
resolve these issues. If the postgresql service is running, it will be
automatically restarted after installing this update.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308605");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-13 18:25:40 +0200 (Tue, 13 Oct 2009)");
 script_cve_id("CVE-2009-0922", "CVE-2009-3230", "CVE-2007-6600");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_name("RedHat Security Advisory RHSA-2009:1484");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://www.postgresql.org/docs/7.4/static/release.html");
 script_xref(name : "URL" , value : "http://www.postgresql.org/docs/8.1/static/release.html");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~7.4.26~1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~7.4.26~1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-debuginfo", rpm:"postgresql-debuginfo~7.4.26~1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~7.4.26~1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~7.4.26~1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-jdbc", rpm:"postgresql-jdbc~7.4.26~1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~7.4.26~1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-pl", rpm:"postgresql-pl~7.4.26~1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-python", rpm:"postgresql-python~7.4.26~1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~7.4.26~1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-tcl", rpm:"postgresql-tcl~7.4.26~1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~7.4.26~1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.1.18~2.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~8.1.18~2.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-debuginfo", rpm:"postgresql-debuginfo~8.1.18~2.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~8.1.18~2.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~8.1.18~2.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-python", rpm:"postgresql-python~8.1.18~2.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-tcl", rpm:"postgresql-tcl~8.1.18~2.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~8.1.18~2.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-pl", rpm:"postgresql-pl~8.1.18~2.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~8.1.18~2.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~8.1.18~2.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
