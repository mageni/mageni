# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2005_085_01.nasl 14202 2019-03-15 09:16:15Z cfischer $
# Description: Auto-generated from the corresponding slackware advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53962");
  script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 14202 $");
  script_name("Slackware Advisory SSA:2005-085-01 Mozilla/Firefox/Thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(9\.1|10\.0|10\.1)");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2005-085-01");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#Mozilla");

  script_tag(name:"insight", value:"New Mozilla packages are available for Slackware 9.1, 10.0, 10.1, and -current
to fix various security issues and bugs. See the referenced Mozilla site for a complete
list of the issues patched.

Also updated are Firefox and Thunderbird in Slackware -current, and GAIM in
Slackware 9.1, 10.0, and 10.1 (which uses the Mozilla NSS libraries).

New versions of the mozilla-plugins symlink creation package are also out for
Slackware 9.1, 10.0, and 10.1.

Just a little note on Slackware security -- I believe the state of Slackware
right now is quite secure.  I know there have been issues announced and fixed
elsewhere, and I am assessing the reality of them (to be honest, it seems the
level of proof needed to announce a security hole these days has fallen close
to zero -- where are the proof-of-concept exploits?)  It is, as always, my
firm intent to keep Slackware as secure as it can possibly be.  I'm still
getting back up to speed (and I do not believe that anything exploitable in
real life is being allowed to slide), but I'm continuing to look over the
various reports and would welcome input at security@slackware.com if you feel
anything important has been overlooked and is in need of attention.  Please
remember that I do read BugTraq and many other security lists.  I am not
asking for duplicates of BugTraq posts unless you have additional proof or
information on the issues, or can explain how an issue affects your own
servers.  This will help me to priorite any work that remains to be done.
Thanks in advance for any helpful comments.");

  script_tag(name:"solution", value:"Upgrade to the new package(s).");

  script_tag(name:"summary", value:"The remote host is missing an update as announced
via advisory SSA:2005-085-01.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

report = "";
res = "";

if((res = isslkpkgvuln(pkg:"gaim", ver:"1.2.0-i486-1", rls:"SLK9.1")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"mozilla", ver:"1.4.4-i486-1", rls:"SLK9.1")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.4.4-noarch-1", rls:"SLK9.1")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"gaim", ver:"1.2.0-i486-1", rls:"SLK10.0")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.6-i486-1", rls:"SLK10.0")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.7.6-noarch-1", rls:"SLK10.0")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"gaim", ver:"1.2.0-i486-1", rls:"SLK10.1")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.6-i486-1", rls:"SLK10.1")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.7.6-noarch-1", rls:"SLK10.1")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}