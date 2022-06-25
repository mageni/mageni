#
#VID 82b55df8-4d5a-11de-8811-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 82b55df8-4d5a-11de-8811-0030843d3802
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: opensll

CVE-2009-1377
The dtls1_buffer_record function in ssl/d1_pkt.c in OpenSSL 0.9.8k and
earlier 0.9.8 versions allows remote attackers to cause a denial of
service (memory consumption) via a large series of 'future epoch' DTLS
records that are buffered in a queue, aka 'DTLS record buffer
limitation bug.'

CVE-2009-1378
Multiple memory leaks in the dtls1_process_out_of_seq_message function
in ssl/d1_both.c in OpenSSL 0.9.8k and earlier 0.9.8 versions allow
remote attackers to cause a denial of service (memory consumption) via
DTLS records that (1) are duplicates or (2) have sequence numbers much
greater than current sequence numbers, aka 'DTLS fragment handling
memory leak.'";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/35128/
http://www.vuxml.org/freebsd/82b55df8-4d5a-11de-8811-0030843d3802.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308429");
 script_version("$Revision: 4847 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-23 10:33:16 +0100 (Fri, 23 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
 script_cve_id("CVE-2009-1377", "CVE-2009-1378");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("FreeBSD Ports: opensll");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"opensll");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.8")>=0 && revcomp(a:bver, b:"0.9.8k_1")<0) {
    txt += 'Package opensll version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
