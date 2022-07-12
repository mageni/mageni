#
#VID 78f456fd-9c87-11dd-a55e-00163e000016
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 78f456fd-9c87-11dd-a55e-00163e000016
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
tag_insight = "The following package is affected: linux-flashplugin

CVE-2007-6243
Adobe Flash Player 9.x up to 9.0.48.0, 8.x up to 8.0.35.0, and 7.x up
to 7.0.70.0 does not sufficiently restrict the interpretation and
usage of cross-domain policy files, which makes it easier for remote
attackers to conduct cross-domain and cross-site scripting (XSS)
attacks.

CVE-2008-3873
The System.setClipboard method in ActionScript in Adobe Flash Player
9.0.124.0 and earlier allows remote attackers to populate the
clipboard with a URL that is difficult to delete and does not require
user interaction to populate the clipboard, as exploited in the wild
in August 2008.

CVE-2007-4324
ActionScript 3 (AS3) in Adobe Flash Player 9.0.47.0, and other
versions and other 9.0.124.0 and earlier versions, allows remote
attackers to bypass the Security Sandbox Model, obtain sensitive
information, and port scan arbitrary hosts via a Flash (SWF) movie
that specifies a connection to make, then uses timing discrepancies
from the SecurityErrorEvent error to determine whether a port is open
or not.  NOTE: 9.0.115.0 introduces support for a workaround, but does
not fix the vulnerability.

CVE-2008-4401
ActionScript in Adobe Flash Player 9.0.124.0 and earlier does not
require user interaction in conjunction with (1) the
FileReference.browse operation in the FileReference upload API or (2)
the FileReference.download operation in the FileReference download
API, which allows remote attackers to create a browse dialog box, and
possibly have unspecified other impact, via an SWF file.

CVE-2008-4503
The Settings Manager in Adobe Flash Player 9.0.124.0 and earlier
allows remote attackers to cause victims to unknowingly click on a
link or dialog via access control dialogs disguised as normal
graphical elements, as demonstrated by hijacking the camera or
microphone, and related to 'clickjacking.'";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.adobe.com/support/security/bulletins/apsb08-18.html
http://www.vuxml.org/freebsd/78f456fd-9c87-11dd-a55e-00163e000016.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301439");
 script_version("$Revision: 4128 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-22 07:37:51 +0200 (Thu, 22 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-11-01 01:55:10 +0100 (Sat, 01 Nov 2008)");
 script_cve_id("CVE-2007-6243", "CVE-2008-3873", "CVE-2007-4324", "CVE-2008-4401", "CVE-2008-4503");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeBSD Ports: linux-flashplugin");



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
bver = portver(pkg:"linux-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"9.0r124_1")<=0) {
    txt += 'Package linux-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
