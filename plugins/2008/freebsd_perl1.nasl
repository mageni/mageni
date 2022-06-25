#
#VID bb33981a-7ac6-11da-bf72-00123f589060
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
   perl
   webmin
   usermin

CVE-2005-3912
Format string vulnerability in miniserv.pl Perl web server in Webmin
before 1.250 and Usermin before 1.180, with syslog logging enabled,
allows remote attackers to cause a denial of service (crash or memory
consumption) and possibly execute arbitrary code via format string
specifiers in the username parameter to the login form, which is
ultimately used in a syslog call.  NOTE: the code execution might be
associated with an issue in Perl.

CVE-2005-3962
Integer overflow in the format string functionality (Perl_sv_vcatpvfn)
in Perl 5.9.2 and 5.8.6 Perl allows attackers to overwrite arbitrary
memory and possibly execute arbitrary code via format string
specifiers with large values, which causes an integer wrap and leads
to a buffer overflow, as demonstrated using format string
vulnerabilities in Perl applications.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://dev.perl.org/perl5/news/2005/perl_patches_fix_sprintf_buffer.html
http://www.dyadsecurity.com/perl-0002.html
http://www.dyadsecurity.com/webmin-0001.html
http://www.webmin.com/security.html
http://www.vuxml.org/freebsd/bb33981a-7ac6-11da-bf72-00123f589060.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303643");
 script_version("$Revision: 4148 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-27 07:32:19 +0200 (Tue, 27 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2005-3912", "CVE-2005-3962");
 script_bugtraq_id(15629);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: perl");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"perl");
if(!isnull(bver) && revcomp(a:bver, b:"5.6.0")>=0 && revcomp(a:bver, b:"5.6.2")<0) {
    txt += 'Package perl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"5.8.0")>=0 && revcomp(a:bver, b:"5.8.7_1")<0) {
    txt += 'Package perl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"webmin");
if(!isnull(bver) && revcomp(a:bver, b:"1.250")<0) {
    txt += 'Package webmin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"usermin");
if(!isnull(bver) && revcomp(a:bver, b:"1.180")<0) {
    txt += 'Package usermin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
