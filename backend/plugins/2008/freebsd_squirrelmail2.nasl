#
#VID af9018b6-a4f5-11da-bb41-0011433a9404
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from vuxml or freebsd advisories
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
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
tag_insight = "The following package is affected: squirrelmail

CVE-2006-0377
CRLF injection vulnerability in SquirrelMail 1.4.0 to 1.4.5 allows
remote attackers to inject arbitrary IMAP commands via newline
characters in the mailbox parameter of the sqimap_mailbox_select
command, aka 'IMAP injection.'

CVE-2006-0195
Interpretation conflict in the MagicHTML filter in SquirrelMail 1.4.0
to 1.4.5 allows remote attackers to conduct cross-site scripting (XSS)
attacks via style sheet specifiers with invalid (1) '/*' and '*/'
comments, or (2) a newline in a 'url' specifier, which is processed by
certain web browsers including Internet Explorer.

CVE-2006-0188
webmail.php in SquirrelMail 1.4.0 to 1.4.5 allows remote attackers to
inject arbitrary web pages into the right frame via a URL in the
right_frame parameter.  NOTE: this has been called a cross-site
scripting (XSS) issue, but it is different than what is normally
identified as XSS.";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";

tag_solution = "Update your system with the appropriate patches or
software upgrades.";
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301433");
 script_version("$Revision: 4188 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-30 07:56:47 +0200 (Fri, 30 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2006-0377", "CVE-2006-0195", "CVE-2006-0188");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_name("FreeBSD Ports: squirrelmail");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
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

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"squirrelmail");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.6")<0) {
    txt += 'Package squirrelmail version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
