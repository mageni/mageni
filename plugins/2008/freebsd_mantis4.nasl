#
#VID 29255141-c3df-11dd-a721-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 29255141-c3df-11dd-a721-0030843d3802
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
tag_insight = "The following package is affected: mantis

CVE-2008-2276
Cross-site request forgery (CSRF) vulnerability in
manage_user_create.php in Mantis 1.1.1 allows remote attackers to
create new administrative users via a crafted link.
CVE-2008-3331
Cross-site scripting (XSS) vulnerability in return_dynamic_filters.php
in Mantis before 1.1.2 allows remote attackers to inject arbitrary web
script or HTML via the filter_target parameter.
CVE-2008-3332
Eval injection vulnerability in adm_config_set.php in Mantis before
1.1.2 allows remote authenticated administrators to execute arbitrary
code via the value parameter.
CVE-2008-3333
Directory traversal vulnerability in core/lang_api.php in Mantis
before 1.1.2 allows remote attackers to include and execute arbitrary
files via the language parameter to the user preferences page
(account_prefs_update.php).";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/30270/
http://www.vuxml.org/freebsd/29255141-c3df-11dd-a721-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300637");
 script_version("$Revision: 4128 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-22 07:37:51 +0200 (Thu, 22 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-12-10 05:23:56 +0100 (Wed, 10 Dec 2008)");
 script_cve_id("CVE-2008-2276", "CVE-2008-3331", "CVE-2008-3332", "CVE-2008-3333");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: mantis");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"mantis");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2")<0) {
    txt += 'Package mantis version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
