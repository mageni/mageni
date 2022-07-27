# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1289.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:1289 ()
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

http://rhn.redhat.com/errata/RHSA-2009-1289.html
http://www.redhat.com/security/updates/classification/#moderate
http://www.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5.4/html/Technical_Notes/mysql.html";

tag_summary = "The remote host is missing updates to MySQL announced in
advisory RHSA-2009:1289.

For details on the issues addressed in this update, please
visit the referenced security advisories.

Note: These updated packages upgrade MySQL to version 5.0.77 to incorporate
numerous upstream bug fixes. Details of these changes are found in the
following MySQL Release Notes:

All MySQL users are advised to upgrade to these updated packages, which
resolve these issues. After installing this update, the MySQL server
daemon (mysqld) will be restarted automatically.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.312019");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-09 02:15:49 +0200 (Wed, 09 Sep 2009)");
 script_cve_id("CVE-2008-2079", "CVE-2008-3963", "CVE-2008-4456", "CVE-2009-2446");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_name("RedHat Security Advisory RHSA-2009:1289");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://dev.mysql.com/doc/refman/5.0/en/news-5-0-77.html");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.77~3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-debuginfo", rpm:"mysql-debuginfo~5.0.77~3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.77~3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.77~3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.77~3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.77~3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
