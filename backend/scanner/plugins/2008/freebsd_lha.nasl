#
#VID 273cc1a3-0d6b-11d9-8a8a-000c41e2cdad
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
tag_insight = "The following package is affected: lha

CVE-2004-0694
** RESERVED **
This candidate has been reserved by an organization or individual that
will use it when announcing a new security problem.  When the
candidate has been publicized, the details for this candidate will be
provided.

CVE-2004-0745
LHA 1.14 and earlier allows attackers to execute arbitrary commands
via a directory with shell metacharacters in its name.

CVE-2004-0769
Buffer overflow in LHA allows remote attackers to execute arbitrary
code via long pathnames in LHarc format 2 headers for a .LHZ archive,
as originally demonstrated using the 'x' option but also exploitable
through 'l' and 'v', and fixed in header.c, a different issue than
CVE-2004-0771.

CVE-2004-0771
Buffer overflow in the extract_one function from lhext.c in LHA may
allow attackers to execute arbitrary code via a long w (working
directory) command line option, a different issue than CVE-2004-0769.
NOTE: this issue may be REJECTED if there are not any cases in which
LHA is setuid or is otherwise used across security boundaries.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://bugs.gentoo.org/show_bug.cgi?id=51285
http://xforce.iss.net/xforce/xfdb/16196
http://marc.theaimsgroup.com/?l=bugtraq&m=108464470103227
http://marc.theaimsgroup.com/?l=bugtraq&m=108668791510153
http://www.vuxml.org/freebsd/273cc1a3-0d6b-11d9-8a8a-000c41e2cdad.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302854");
 script_version("$Revision: 4125 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-21 07:39:51 +0200 (Wed, 21 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-0694", "CVE-2004-0745", "CVE-2004-0769", "CVE-2004-0771");
 script_bugtraq_id(10354);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: lha");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
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
bver = portver(pkg:"lha");
if(!isnull(bver) && revcomp(a:bver, b:"1.14i_6")<0) {
    txt += 'Package lha version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
