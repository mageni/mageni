#
#VID fdad8a87-7f94-11d9-a9e7-0001020eed82
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
tag_insight = "The following package is affected: awstats

CVE-2005-0362
awstats.pl in AWStats 6.2 allows remote attackers to execute arbitrary
commands via shell metacharacters in the (1) 'pluginmode', (2)
'loadplugin', or (3) 'noloadplugin' parameters.

CVE-2005-0363
awstats.pl in AWStats 4.0 and 6.2 allows remote attackers to execute
arbitrary commands via shell metacharacters in the config parameter.

CVE-2005-0435
awstats.pl in AWStats 6.3 and 6.4 allows remote attackers to read
server web logs by setting the loadplugin and pluginmode parameters to
rawlog.

CVE-2005-0436
Direct code injection vulnerability in awstats.pl in AWStats 6.3 and
6.4 allows remote attackers to execute portions of Perl code via the
PluginMode parameter.

CVE-2005-0437
Directory traversal vulnerability in awstats.pl in AWStats 6.3 and 6.4
allows remote attackers to include arbitrary Perl modules via .. (dot
dot) sequences in the loadplugin parameter.

CVE-2005-0438
awstats.pl in AWStats 6.3 and 6.4 allows remote attackers to obtain
sensitive information by setting the debug parameter.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://awstats.sourceforge.net/docs/awstats_changelog.txt
http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=294488
http://packetstormsecurity.nl/0501-exploits/AWStatsVulnAnalysis.pdf
http://marc.theaimsgroup.com/?l=bugtraq&m=110840530924124
http://www.vuxml.org/freebsd/fdad8a87-7f94-11d9-a9e7-0001020eed82.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301502");
 script_version("$Revision: 4075 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-15 15:13:05 +0200 (Thu, 15 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2005-0362", "CVE-2005-0363", "CVE-2005-0435", "CVE-2005-0436", "CVE-2005-0437", "CVE-2005-0438");
 script_bugtraq_id(12543,12545);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("FreeBSD Ports: awstats");



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
bver = portver(pkg:"awstats");
if(!isnull(bver) && revcomp(a:bver, b:"6.4")<0) {
    txt += 'Package awstats version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
