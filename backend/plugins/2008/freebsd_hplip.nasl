#
#VID 37940643-be1b-11dd-a578-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 37940643-be1b-11dd-a578-0030843d3802
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
tag_insight = "The following package is affected: hplip

CVE-2008-2940
The alert-mailing implementation in HP Linux Imaging and Printing
(HPLIP) 1.6.7 allows local users to gain privileges and send e-mail
messages from the root account via vectors related to the setalerts
message, and lack of validation of the device URI associated with an
event message.

CVE-2008-2941
The hpssd message parser in hpssd.py in HP Linux Imaging and Printing
(HPLIP) 1.6.7 allows local users to cause a denial of service (process
stop) via a crafted packet, as demonstrated by sending 'msg=0' to TCP
port 2207.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://rhn.redhat.com/errata/RHSA-2008-0818.html
http://secunia.com/advisories/31470
http://www.vuxml.org/freebsd/37940643-be1b-11dd-a578-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301423");
 script_version("$Revision: 4118 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-20 07:32:38 +0200 (Tue, 20 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-12-03 18:25:22 +0100 (Wed, 03 Dec 2008)");
 script_cve_id("CVE-2008-2940", "CVE-2008-2941");
 script_bugtraq_id(30683);
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: hplip");



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
bver = portver(pkg:"hplip");
if(!isnull(bver) && revcomp(a:bver, b:"2.8.2_3")<0) {
    txt += 'Package hplip version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
