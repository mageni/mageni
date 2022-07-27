# OpenVAS Vulnerability Test
# $Id: deb_1516_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1516-1 (dovecot)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
tag_insight = "Prior to this update, the default configuration for Dovecot used by
Debian runs the server daemons with group mail privileges.  This means
that users with write access to their mail directory by other means
(for example, through an SSH login) could read mailboxes owned by
other users for which they do not have direct write access
(CVE-2008-1199).  In addition, an internal interpretation conflict in
password handling has been addressed proactively, even though it is
not known to be exploitable (CVE-2008-1218).

Note that applying this update requires manual action: The
configuration setting mail_extra_groups = mail has been replaced
with mail_privileged_group = mail.  The update will show a
configuration file conflict in /etc/dovecot/dovecot.conf.  It is
recommended that you keep the currently installed configuration file,
and change the affected line.  For your reference, the sample
configuration (without your local changes) will have been written to
/etc/dovecot/dovecot.conf.dpkg-new.

If your current configuration uses mail_extra_groups with a value
different from mail, you may have to resort to the
mail_access_groups configuration directive.

For the stable distribution (etch), these problems have been fixed in
version 1.0.rc15-2etch4.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.13-1.

For the old stable distribution (sarge), no updates are provided.
We recommend that you consider upgrading to the stable distribution.";
tag_summary = "The remote host is missing an update to dovecot
announced via advisory DSA 1516-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201516-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302329");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-03-19 20:30:32 +0100 (Wed, 19 Mar 2008)");
 script_cve_id("CVE-2008-1199", "CVE-2008-1218");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1516-1 (dovecot)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1.0.rc15-2etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-common", ver:"1.0.rc15-2etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1.0.rc15-2etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
