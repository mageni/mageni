#
#VID dd943fbb-d0fe-11df-95a8-00219b0fc4d8
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID dd943fbb-d0fe-11df-95a8-00219b0fc4d8
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: apr

CVE-2009-3560
The big2_toUtf8 function in lib/xmltok.c in libexpat in Expat 2.0.1,
as used in the XML-Twig module for Perl, allows context-dependent
attackers to cause a denial of service (application crash) via an XML
document with malformed UTF-8 sequences that trigger a buffer
over-read, related to the doProlog function in lib/xmlparse.c, a
different vulnerability than CVE-2009-2625 and CVE-2009-3720.

CVE-2009-3720
The updatePosition function in lib/xmltok_impl.c in libexpat in Expat
2.0.1, as used in Python, PyXML, w3c-libwww, and other software,
allows context-dependent attackers to cause a denial of service
(application crash) via an XML document with crafted UTF-8 sequences
that trigger a buffer over-read, a different vulnerability than
CVE-2009-2625.

CVE-2010-1623
The apr_brigade_split_line function in buckets/apr_brigade.c in the
Apache Portable Runtime Utility library (aka APR-util) before 1.3.10,
as used in the mod_reqtimeout module in the Apache HTTP Server and
other software, allows remote attackers to cause a denial of service
(memory consumption) via unspecified vectors.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.apache.org/dist/apr/CHANGES-APR-UTIL-1.3
http://secunia.com/advisories/41701
http://www.vuxml.org/freebsd/dd943fbb-d0fe-11df-95a8-00219b0fc4d8.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";




if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314115");
 script_version("$Revision: 8269 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-10-10 19:35:00 +0200 (Sun, 10 Oct 2010)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2009-3560", "CVE-2009-3720", "CVE-2010-1623");
 script_bugtraq_id(43673);
 script_name("FreeBSD Ports: apr");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"apr");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2.1.3.10")<0) {
    txt += 'Package apr version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
