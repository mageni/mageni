# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1185.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:1185 ()
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
advisory RHSA-2009:1185.

SeaMonkey is an open source Web browser, email and newsgroup client, IRC
chat client, and HTML editor.

Moxie Marlinspike reported a heap overflow flaw in a regular expression
parser in the NSS library (provided by SeaMonkey) used to match common
names in certificates. A malicious website could present a
carefully-crafted certificate in such a way as to trigger the heap
overflow, leading to a crash or, possibly, arbitrary code execution with
the permissions of the user running SeaMonkey. (CVE-2009-2404)

Note: in order to exploit this issue without further user interaction, the
carefully-crafted certificate would need to be signed by a Certificate
Authority trusted by SeaMonkey, otherwise SeaMonkey presents the victim
with a warning that the certificate is untrusted. Only if the user then
accepts the certificate will the overflow take place.

All SeaMonkey users should upgrade to these updated packages, which contain
a backported patch to correct this issue. After installing the updated
packages, SeaMonkey must be restarted for the update to take effect.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309108");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_cve_id("CVE-2009-2404");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("RedHat Security Advisory RHSA-2009:1185");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1185.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#critical");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.0.9~0.41.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-chat", rpm:"seamonkey-chat~1.0.9~0.41.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~1.0.9~0.41.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-devel", rpm:"seamonkey-devel~1.0.9~0.41.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.0.9~0.41.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-js-debugger", rpm:"seamonkey-js-debugger~1.0.9~0.41.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.0.9~0.41.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-nspr", rpm:"seamonkey-nspr~1.0.9~0.41.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-nspr-devel", rpm:"seamonkey-nspr-devel~1.0.9~0.41.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-nss", rpm:"seamonkey-nss~1.0.9~0.41.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"seamonkey-nss-devel", rpm:"seamonkey-nss-devel~1.0.9~0.41.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
