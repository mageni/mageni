#
#ADV FreeBSD-SA-03:15.openssh.asc
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
#

tag_insight = "OpenSSH is a free version of the SSH protocol suite of network
connectivity tools.  OpenSSH encrypts all traffic (including
passwords) to effectively eliminate eavesdropping, connection
hijacking, and other network-level attacks.  Additionally, OpenSSH
provides a myriad of secure tunneling capabilities, as well as a
variety of authentication methods.

The SSH protocol exists in two versions, hereafter named simply `ssh1'
and `ssh2'.  The ssh1 protocol is a legacy protocol for which there
exists no formal specification, while the ssh2 protocol is the product
of the IETF SECSH working group and is defined by a series of IETF
draft standards.

The ssh2 protocol supports a wide range of authentication
mechanisms, including a generic challenge / response mechanism, called
`keyboard-interactive' or `kbdint', which can be adapted to serve any
authentication scheme in which the server and client exchange a
arbitrarily long series of challenges and responses.  In particular,
this mechanism is used in OpenSSH to support PAM authentication.

The ssh1 protocol, on the other hand, supports a much narrower range
of authentication mechanisms.  Its challenge / response mechanisms,
called `TIS', allows for only one challenge from the server and one
response from the client.  OpenSSH contains interface code which
allows kbdint authentication back-ends to be used for ssh1 TIS
authentication, provided they only emit one challenge and expect only
one response.

Finally, recent versions of OpenSSH implement a mechanism called
`privilege separation' in which the task of communicating with the
client is delegated to an unprivileged child process, while the
privileged parent process performs the actual authentication and
double-checks every important decision taken by its unprivileged
child.

1) Insufficient checking in the ssh1 challenge / response interface
   code, combined with a peculiarity of the PAM kbdint back-end,
   causes OpenSSH to ignore a negative result from PAM (but not from
   any other kbdint back-end).

2) A variable used by the PAM conversation function to store
   challenges and the associated client responses is incorrectly
   interpreted as an array of pointers to structures instead of a
   pointer to an array of structures.

3) When challenge / response authentication is used with protocol
   version 1, and a legitimate user interrupts challenge / response
   authentication but successfully authenticates through some other
   mechanism (such as password authentication), the server fails to
   reclaim resources allocated by the challenge / response mechanism,
   including the child process used for PAM authentication.  When a
   certain number of leaked processes is reached, the master server
   process will refuse subsequent client connections.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-03:15.openssh.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-03:15.openssh.asc";

                                                                                
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303617");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 name = "FreeBSD Security Advisory (FreeBSD-SA-03:15.openssh.asc)";
 script_name(name);



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 family = "FreeBSD Local Security Checks";
 script_family(family);
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdpatchlevel", "login/SSH/success");
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
vuln = 0;
if(patchlevelcmp(rel:"5.1", patchlevel:"7")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"9")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.7", patchlevel:"19")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.6.2", patchlevel:"22")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
