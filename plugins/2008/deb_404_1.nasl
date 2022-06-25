# OpenVAS Vulnerability Test
# $Id: deb_404_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 404-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "The rsync team has received evidence that a vulnerability in all
versions of rsync prior to 2.5.7, a fast remote file copy program, was
recently used in combination with a Linux kernel vulnerability to
compromise the security of a public rsync server.

While this heap overflow vulnerability could not be used by itself to
obtain root access on an rsync server, it could be used in combination
with the recently announced do_brk() vulnerability in the Linux kernel
to produce a full remote compromise.

Please note that this vulnerability only affects the use of rsync as
an rsync server.  To see if you are running a rsync server you
should use the command netstat -a -n to see if you are listening on
TCP port 873.  If you are not listening on TCP port 873 then you are
not running an rsync server.

For the stable distribution (woody) this problem has been fixed in
version 2.5.5-0.2.

For the unstable distribution (sid) this problem has been fixed in
version 2.5.6-1.1.

However, since the Debian infrastructure is not yet fully functional
after the recent break-in, packages for the unstable distribution are
not able to enter the archive for a while.  Hence they were placed in
my home directory on the security machine:

<http://klecker.debian.org/~joey/rsync/>

We recommend that you upgrade your rsync package immediately if you";
tag_summary = "The remote host is missing an update to rsync
announced via advisory DSA 404-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20404-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300929");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(9153);
 script_cve_id("CVE-2003-0962");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 404-1 (rsync)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"rsync", ver:"2.5.5-0.2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
