# OpenVAS Vulnerability Test
# $Id: deb_073_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 073-1
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
tag_insight = "The Horde team released version 2.2.6 of IMP (a web based IMAP mail
program) which fixes three security problems. Their release announcement
describes them as follows:

1. A PHPLIB vulnerability allowed an attacker to provide a value for the
array element $_PHPLIB[libdir], and thus to get scripts from another
server to load and execute.  This vulnerability is remotely
exploitable.  (Horde 1.2.x ships with its own customized version of
PHPLIB, which has now been patched to prevent this problem.)

2. By using tricky encodings of 'javascript:' an attacker can cause
malicious JavaScript code to execute in the browser of a user reading
email sent by attacker.  (IMP 2.2.x already filters many such
patterns; several new ones that were slipping past the filters are
now blocked.)

3. A hostile user that can create a publicly-readable file named
'prefs.lang' somewhere on the Apache/PHP server can cause that file
to be executed as PHP code.  The IMP configuration files could thus
be read, the Horde database password used to read and alter the
database used to store contacts and preferences, etc.  We do not
believe this is remotely exploitable directly through Apache/PHP/IMP;
however, shell access to the server or other means (e.g., FTP) could
be used to create this file.

This has been fixed in version 2:2.2.6-0.potato.1 . Please note you
will also need to upgrade the horde package to the same version.";
tag_summary = "The remote host is missing an update to imp
announced via advisory DSA 073-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20073-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302365");
 script_cve_id("CVE-2001-1257","CVE-2001-1258","CVE-2001-1370");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 073-1 (imp)");



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
if ((res = isdpkgvuln(pkg:"horde", ver:"1.2.6-0.potato.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imp", ver:"2.2.6-0.potato.1", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
