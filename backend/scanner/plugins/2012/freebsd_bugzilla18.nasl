###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_bugzilla18.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 58253655-d82c-11e1-907c-20cf30e32f6d
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71514");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2012-1968", "CVE-2012-1969");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
  script_name("FreeBSD Ports: bugzilla");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: bugzilla

CVE-2012-1968
Bugzilla 4.1.x and 4.2.x before 4.2.2 and 4.3.x before 4.3.2 uses
bug-editor privileges instead of bugmail-recipient privileges during
construction of HTML bugmail documents, which allows remote attackers
to obtain sensitive description information by reading the tooltip
portions of an HTML e-mail message.
CVE-2012-1969
The get_attachment_link function in Template.pm in Bugzilla 2.x and
3.x before 3.6.10, 3.7.x and 4.0.x before 4.0.7, 4.1.x and 4.2.x
before 4.2.2, and 4.3.x before 4.3.2 does not check whether an
attachment is private before presenting the attachment description
within a public comment, which allows remote attackers to obtain
sensitive description information by reading a comment.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=777398");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=777586");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/58253655-d82c-11e1-907c-20cf30e32f6d.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"bugzilla");
if(!isnull(bver) && revcomp(a:bver, b:"3.6.0")>=0 && revcomp(a:bver, b:"3.6.10")<0) {
  txt += "Package bugzilla version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"4.0.0")>=0 && revcomp(a:bver, b:"4.0.7")<0) {
  txt += "Package bugzilla version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"4.2.0")>=0 && revcomp(a:bver, b:"4.2.2")<0) {
  txt += "Package bugzilla version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}