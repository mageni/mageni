# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1530.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:1530 ()
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
advisory RHSA-2009:1530.

Mozilla Firefox is an open source Web browser. XULRunner provides the XUL
Runtime environment for Mozilla Firefox. nspr provides the Netscape
Portable Runtime (NSPR).

A flaw was found in the way Firefox handles form history. A malicious web
page could steal saved form data by synthesizing input events, causing the
browser to auto-fill form fields (which could then be read by an attacker).
(CVE-2009-3370)

A flaw was found in the way Firefox creates temporary file names for
downloaded files. If a local attacker knows the name of a file Firefox is
going to download, they can replace the contents of that file with
arbitrary contents. (CVE-2009-3274)

A flaw was found in the Firefox Proxy Auto-Configuration (PAC) file
processor. If Firefox loads a malicious PAC file, it could crash Firefox
or, potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2009-3372)

A heap-based buffer overflow flaw was found in the Firefox GIF image
processor. A malicious GIF image could crash Firefox or, potentially,
execute arbitrary code with the privileges of the user running Firefox.
(CVE-2009-3373)

A heap-based buffer overflow flaw was found in the Firefox string to
floating point conversion routines. A web page containing malicious
JavaScript could crash Firefox or, potentially, execute arbitrary code with
the privileges of the user running Firefox. (CVE-2009-1563)

A flaw was found in the way Firefox handles text selection. A malicious
website may be able to read highlighted text in a different domain (e.g.
another website the user is viewing), bypassing the same-origin policy.
(CVE-2009-3375)

A flaw was found in the way Firefox displays a right-to-left override
character when downloading a file. In these cases, the name displayed in
the title bar differs from the name displayed in the dialog body. An
attacker could use this flaw to trick a user into downloading a file that
has a file name or extension that differs from what the user expected.
(CVE-2009-3376)

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2009-3374, CVE-2009-3380, CVE-2009-3382)

For technical details regarding these flaws, refer to the Mozilla security
advisories for Firefox 3.0.15. You can find a link to the Mozilla
advisories in the References section of this errata.

All Firefox users should upgrade to these updated packages, which contain
Firefox version 3.0.15, which corrects these issues. After installing the
update, Firefox must be restarted for the changes to take effect.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311027");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
 script_cve_id("CVE-2009-0689", "CVE-2009-3274", "CVE-2009-3370", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3380", "CVE-2009-3382");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("RedHat Security Advisory RHSA-2009:1530");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1530.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#critical");
 script_xref(name : "URL" , value : "http://www.mozilla.org/security/known-vulnerabilities/firefox30.html#firefox3.0.15");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.15~3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~3.0.15~3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.7.6~1.el4_8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr-debuginfo", rpm:"nspr-debuginfo~4.7.6~1.el4_8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.7.6~1.el4_8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.15~3.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~3.0.15~3.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.7.6~1.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr-debuginfo", rpm:"nspr-debuginfo~4.7.6~1.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.0.15~3.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~1.9.0.15~3.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.7.6~1.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~1.9.0.15~3.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xulrunner-devel-unstable", rpm:"xulrunner-devel-unstable~1.9.0.15~3.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
