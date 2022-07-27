#
#VID 2de14f7a-dad9-11d8-b59a-00061bc2ad93
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
tag_insight = "The following packages are affected:
   samba
   ja-samba

CVE-2004-0600
Buffer overflow in the Samba Web Administration Tool (SWAT) in Samba
3.0.2 to 3.0.4 allows remote attackers to execute arbitrary code via
an invalid base-64 character during HTTP basic authentication.

CVE-2004-0686
Buffer overflow in Samba 2.2.x to 2.2.9, and 3.0.0 to 3.0.4, when the
'mangling method = hash' option is enabled in smb.conf, has unknown
impact and attack vectors.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304301");
 script_version("$Revision: 4175 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-29 07:45:50 +0200 (Thu, 29 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-0600", "CVE-2004-0686");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: samba");


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
 script_xref(name : "URL" , value : "http://www.samba.org/samba/whatsnew/samba-3.0.5.html");
 script_xref(name : "URL" , value : "http://www.samba.org/samba/whatsnew/samba-2.2.10.html");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/12130");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/369698");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/369706");
 script_xref(name : "URL" , value : "http://www.vuxml.org/freebsd/2de14f7a-dad9-11d8-b59a-00061bc2ad93.html");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"samba");
if(!isnull(bver) && revcomp(a:bver, b:"3")>=0 && revcomp(a:bver, b:"3.0.5,1")<0) {
    txt += 'Package samba version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.2.10")<0) {
    txt += 'Package samba version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-samba");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.10.j1.0")<0) {
    txt += 'Package ja-samba version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
