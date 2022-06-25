#
#VID 3fbf9db2-658b-11d9-abad-000a95bc6fae
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
   de-netscape7
   fr-netscape7
   ja-netscape7
   netscape7
   pt_BR-netscape7
   mozilla-gtk1
   linux-mozilla
   linux-mozilla-devel
   mozilla
   de-linux-netscape
   fr-linux-netscape
   ja-linux-netscape
   linux-netscape
   mozilla+ipv6
   mozilla-embedded
   mozilla-gtk2
   mozilla-gtk

CVE-2004-1316
Heap-based buffer overflow in MSG_UnEscapeSearchUrl in
nsNNTPProtocol.cpp for Mozilla 1.7.3 and earlier allows remote
attackers to cause a denial of service (application crash) via an NNTP
URL (news:) with a trailing '\' (backslash) character, which prevents
a string from being NULL terminated.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://isec.pl/vulnerabilities/isec-0020-mozilla.txt
http://marc.theaimsgroup.com/?l=bugtraq&m=110436284718949
http://www.vuxml.org/freebsd/3fbf9db2-658b-11d9-abad-000a95bc6fae.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304048");
 script_version("$Revision: 4078 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-16 07:34:17 +0200 (Fri, 16 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(12131);
 script_cve_id("CVE-2004-1316");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("mozilla -- heap overflow in NNTP handler");



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
bver = portver(pkg:"de-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package de-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"fr-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package fr-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package ja-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pt_BR-netscape7");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
    txt += 'Package pt_BR-netscape7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla-gtk1");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.5")<0) {
    txt += 'Package mozilla-gtk1 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.5")<0) {
    txt += 'Package linux-mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-mozilla-devel");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.5")<0) {
    txt += 'Package linux-mozilla-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.5,2")<0) {
    txt += 'Package mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"de-linux-netscape");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package de-linux-netscape version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"fr-linux-netscape");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package fr-linux-netscape version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-linux-netscape");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package ja-linux-netscape version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-netscape");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package linux-netscape version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mozilla+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla-embedded");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mozilla-embedded version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mozilla-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mozilla-gtk");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
    txt += 'Package mozilla-gtk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
