# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
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
tag_insight = "An error in the usage of the ssl-cert eclass within multiple ebuilds might
allow for disclosure of generated SSL private keys.";
tag_solution = "Upgrading to newer versions of the above packages will neither remove
possibly compromised SSL certificates, nor old binary packages. Please
remove the certificates installed by Portage, and then emerge an upgrade
to the package.

All Conserver users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-admin/conserver-8.1.16'

All Postfix 2.4 users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-mta/postfix-2.4.6-r2'

All Postfix 2.3 users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-mta/postfix-2.3.8-r1'

All Postfix 2.2 users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-mta/postfix-2.2.11-r1'

All Netkit FTP Server users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-ftp/netkit-ftpd-0.17-r7'

All ejabberd users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/ejabberd-1.1.3'

All UnrealIRCd users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-irc/unrealircd-3.2.7-r2'

All Cyrus IMAP Server users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/cyrus-imapd-2.3.9-r1'

All Dovecot users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/dovecot-1.0.10'

All stunnel 4 users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/stunnel-4.21'

All InterNetNews users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-nntp/inn-2.4.3-r1'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200803-30
http://bugs.gentoo.org/show_bug.cgi?id=174759";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200803-30.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302656");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2008-1383");
 script_tag(name:"cvss_base", value:"1.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
 script_name("Gentoo Security Advisory GLSA 200803-30 (ssl-cert.eclass)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
 script_family("Gentoo Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
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

include("pkg-lib-gentoo.inc");

res = "";
report = "";
if ((res = ispkgvuln(pkg:"app-admin/conserver", unaffected: make_list("ge 8.1.16"), vulnerable: make_list("lt 8.1.16"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-mta/postfix", unaffected: make_list("ge 2.4.6-r2", "rge 2.3.8-r1", "rge 2.2.11-r1"), vulnerable: make_list("lt 2.4.6-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-ftp/netkit-ftpd", unaffected: make_list("ge 0.17-r7"), vulnerable: make_list("lt 0.17-r7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-im/ejabberd", unaffected: make_list("ge 1.1.3"), vulnerable: make_list("lt 1.1.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-irc/unrealircd", unaffected: make_list("ge 3.2.7-r2"), vulnerable: make_list("lt 3.2.7-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-mail/cyrus-imapd", unaffected: make_list("ge 2.3.9-r1"), vulnerable: make_list("lt 2.3.9-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-mail/dovecot", unaffected: make_list("ge 1.0.10"), vulnerable: make_list("lt 1.0.10"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-misc/stunnel", unaffected: make_list("ge 4.21-r1", "lt 4.0"), vulnerable: make_list("lt 4.21-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-nntp/inn", unaffected: make_list("ge 2.4.3-r1"), vulnerable: make_list("lt 2.4.3-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
