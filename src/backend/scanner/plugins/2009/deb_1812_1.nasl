# OpenVAS Vulnerability Test
# $Id: deb_1812_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1812-1 (apr-util)
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
tag_insight = "Apr-util, the Apache Portable Runtime Utility library, is used by
Apache 2.x, Subversion, and other applications. Two denial of service
vulnerabilities have been found in apr-util:

kcope discovered a flaw in the handling of internal XML entities in
the apr_xml_* interface that can be exploited to use all available
memory. This denial of service can be triggered remotely in the Apache
mod_dav and mod_dav_svn modules. (No CVE id yet)

Matthew Palmer discovered an underflow flaw in the
apr_strmatch_precompile function that can be exploited to cause a
daemon crash. The vulnerability can be triggered (1) remotely in
mod_dav_svn for Apache if the SVNMasterURIdirective is in use, (2)
remotely in mod_apreq2 for Apache or other applications using
libapreq2, or (3) locally in Apache by a crafted .htaccess file.
(CVE-2009-0023)

Other exploit paths in other applications using apr-util may exist.

If you use Apache, or if you use svnserve in standalone mode, you need
to restart the services after you upgraded the libaprutil1 package.


For the stable distribution (lenny), these problems have been fixed in
version 1.2.12+dfsg-8+lenny2.

The oldstable distribution (etch), these problems have been fixed in
version 1.2.7+dfsg-2+etch2.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems will be fixed soon.

We recommend that you upgrade your apr-util packages.";
tag_summary = "The remote host is missing an update to apr-util
announced via advisory DSA 1812-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201812-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311671");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-09 19:38:29 +0200 (Tue, 09 Jun 2009)");
 script_cve_id("CVE-2009-0023");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 1812-1 (apr-util)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
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

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libaprutil1", ver:"1.2.7+dfsg-2+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dev", ver:"1.2.7+dfsg-2+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dbg", ver:"1.2.7+dfsg-2+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dbg", ver:"1.2.12+dfsg-8+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1-dev", ver:"1.2.12+dfsg-8+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libaprutil1", ver:"1.2.12+dfsg-8+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
