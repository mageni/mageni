# OpenVAS Vulnerability Test
# $Id: deb_1919_2.nasl 8274 2018-01-03 07:28:17Z teissa $
# Description: Auto-generated from advisory DSA 1919-2 (smarty)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "A regression was found in the patch applied in DSA 1919-1 to smarty,
which caused compilation failures on some specific templates. This
update corrects the fix. For reference, the full advisory text below.

Several remote vulnerabilities have been discovered in Smarty, a PHP
templating engine. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2008-4810

The _expand_quoted_text function allows for certain restrictions in
templates, like function calling and PHP execution, to be bypassed.

CVE-2009-1669

The smarty_function_math function allows context-dependent attackers
to execute arbitrary commands via shell metacharacters in the equation
attribute of the math function.

For the stable distribution (lenny), this problem has been fixed in
version 2.6.20-1.3.

The testing (squeeze) and unstable distribution (sid) are not affected
by this regression.

We recommend that you upgrade your smarty package.";
tag_summary = "The remote host is missing an update to smarty
announced via advisory DSA 1919-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201919-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314231");
 script_version("$Revision: 8274 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2008-4810", "CVE-2009-1669");
 script_name("Debian Security Advisory DSA 1919-2 (smarty)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"smarty", ver:"2.6.20-1.3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
