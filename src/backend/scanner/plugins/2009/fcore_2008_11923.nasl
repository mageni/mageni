# OpenVAS Vulnerability Test
# $Id: fcore_2008_11923.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2008-11923 (lighttpd)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
tag_insight = "This update fixes some moderate security issues and includes a few enhancements.

ChangeLog:

* Wed Dec 24 2008 Matthias Saou  1.4.20-6
- Partially revert last change by creating a spawn-fastcgi symlink, so that
nothing breaks currently (especially for EL).
- Install empty poweredby image on RHEL since the symlink's target is missing.
- Split spawn-fcgi off in its own sub-package, have fastcgi package require it
to provide backwards compatibility.
* Mon Dec 22 2008 Matthias Saou  1.4.20-3
- Rename spawn-fastcgi to lighttpd-spawn-fastcgi to avoid clash with other
packages providing it for their own needs (#472749). It's not used as-is
by lighttpd, so it shouldn't be a problem... at worst, some custom scripts
will need to be updated.
* Mon Dec 22 2008 Matthias Saou  1.4.20-2
- Include conf.d/*.conf configuration snippets (#444953).
- Mark the default index.html in order to not loose changes upon upgrade if it
was edited or replaced with a different file (#438564).
- Include patch to add the INIT INFO block to the init script (#246973).";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update lighttpd' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2008-11923";
tag_summary = "The remote host is missing an update to lighttpd
announced via advisory FEDORA-2008-11923.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304402");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
 script_cve_id("CVE-2008-4298", "CVE-2008-4359", "CVE-2008-4360");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_name("Fedora Core 9 FEDORA-2008-11923 (lighttpd)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Fedora Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=464637");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=465751");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=465752");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"lighttpd", rpm:"lighttpd~1.4.20~6.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lighttpd-fastcgi", rpm:"lighttpd-fastcgi~1.4.20~6.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lighttpd-mod_geoip", rpm:"lighttpd-mod_geoip~1.4.20~6.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lighttpd-mod_mysql_vhost", rpm:"lighttpd-mod_mysql_vhost~1.4.20~6.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"spawn-fcgi", rpm:"spawn-fcgi~1.4.20~6.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lighttpd-debuginfo", rpm:"lighttpd-debuginfo~1.4.20~6.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
