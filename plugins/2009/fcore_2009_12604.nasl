# OpenVAS Vulnerability Test
# $Id: fcore_2009_12604.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-12604 (httpd)
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
tag_insight = "The Apache HTTP Server is a powerful, efficient, and extensible
web server.

Update Information:

This update contains the latest stable release of Apache httpd. Three security
fixes are included, along with several minor bug fixes.    A flaw was found in
the way the TLS/SSL (Transport Layer Security/Secure Sockets Layer) protocols
handle session renegotiation. A man-in-the-middle attacker could use this flaw
to prefix arbitrary plain text to a client's session (for example, an HTTPS
connection to a website). This could force the server to process an attacker's
request as if authenticated using the victim's credentials. This update
partially mitigates this flaw for SSL sessions to HTTP servers using mod_ssl by
rejecting client-requested renegotiation. (CVE-2009-3555)    Note: This update
does not fully resolve the issue for HTTPS servers. An attack is still possible
in configurations that require a server-initiated renegotiation

A NULL pointer dereference flaw was found in the Apache mod_proxy_ftp module. A
malicious FTP server to which requests are being proxied could use this flaw to
crash an httpd child process via a malformed reply to the EPSV or PASV commands,
resulting in a limited denial of service. (CVE-2009-3094)

A second flaw was found in the Apache mod_proxy_ftp module. In a reverse
proxy configuration, a remote attacker could use this flaw to bypass
intended access restrictions by creating a carefully-crafted HTTP
Authorization header, allowing the attacker to send arbitrary commands
to the FTP server. (CVE-2009-3095)

See the upstream changes file for further information:
http://www.apache.org/dist/httpd/CHANGES_2.2.14

ChangeLog:

* Thu Dec  3 2009 Joe Orton  - 2.2.14-1
- update to 2.2.14
- Requires(pre): httpd in mod_ssl subpackage (#543275)
- add partial security fix for CVE-2009-3555 (#533125)
- add condrestart in posttrans (#491567)";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update httpd' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-12604";
tag_summary = "The remote host is missing an update to httpd
announced via advisory FEDORA-2009-12604.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307309");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
 script_cve_id("CVE-2009-3555", "CVE-2009-3094", "CVE-2009-3095");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Fedora Core 10 FEDORA-2009-12604 (httpd)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=521619");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=522209");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.14~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.14~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.14~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.2.14~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.14~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.2.14~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
