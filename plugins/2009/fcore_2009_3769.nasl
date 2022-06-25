# OpenVAS Vulnerability Test
# $Id: fcore_2009_3769.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-3769 (cups)
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
tag_insight = "This update fixes several security issues: CVE-2009-0163, CVE-2009-0164,
CVE-2009-0146, CVE-2009-0147, and CVE-2009-0166.

PDF files are now converted to PostScript using the poppler package's
pdftops program.    NOTE: If your CUPS server is accessed using a
hostname or hostnames not known to the server itself you must add
ServerAlias hostname to cupsd.conf for each such name.  The special
line ServerAlias * disables checking (but this allows DNS rebinding attacks).

ChangeLog:

* Tue Apr 21 2009 Tim Waugh  1:1.3.10-1
- 1.3.10.  No longer need ext, includeifexists, str2988,
CVE-2008-5183, CVE-2008-5286, str3077, str3078, str3059, str3055 patches.
- Requires poppler-utils.
- NOTE: If your CUPS server is accessed using a hostname or hostnames
not known to the server itself you must add ServerAlias hostname
for each such name.  The special line ServerAlias * disables checking
(but this allows DNS rebinding attacks).";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update cups' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3769";
tag_summary = "The remote host is missing an update to cups
announced via advisory FEDORA-2009-3769.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307870");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-28 20:40:12 +0200 (Tue, 28 Apr 2009)");
 script_cve_id("CVE-2009-0163", "CVE-2009-0164", "CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2008-5183", "CVE-2008-5286", "CVE-2008-1722");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Fedora Core 10 FEDORA-2009-3769 (cups)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Fedora Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=490597");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=490596");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=490612");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=490614");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=490625");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.3.10~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.3.10~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.3.10~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-lpd", rpm:"cups-lpd~1.3.10~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-php", rpm:"cups-php~1.3.10~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.3.10~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
