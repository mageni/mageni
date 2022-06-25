#
#ADV FreeBSD-SA-09:05.telnetd.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-09:05.telnetd.asc
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

tag_insight = "The FreeBSD telnet daemon, telnetd(8), implements the server side of the
TELNET virtual terminal protocol.  It has been disabled by default in
FreeBSD since August 2001, and due to the lack of cryptographic security
in the TELNET protocol, it is strongly recommended that the SSH protocol
be used instead.  The FreeBSD telnet daemon can be enabled via the
/etc/inetd.conf configuration file and the inetd(8) daemon.

The TELNET protocol allows a connecting client to specify environment
variables which should be set in any created login session; this is used,
for example, to specify terminal settings.

In order to prevent environment variable based attacks, telnetd(8) scrubs
its environment; however, recent changes in FreeBSD's environment-handling
code rendered telnetd's scrubbing inoperative, thereby allowing potentially
harmful environment variables to be set.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-09:05.telnetd.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-09:05.telnetd.asc";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310816");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-02-18 23:13:28 +0100 (Wed, 18 Feb 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 name = "FreeBSD Security Advisory (FreeBSD-SA-09:05.telnetd.asc)";
 script_name(name);



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 family = "FreeBSD Local Security Checks";
 script_family(family);
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdpatchlevel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");
vuln = 0;
if(patchlevelcmp(rel:"7.1", patchlevel:"10")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.0", patchlevel:"3")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
