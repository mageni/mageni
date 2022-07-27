###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_bugzilla20.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 2b841f88-2e8d-11e2-ad21-20cf30e32f6d
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
  script_oid("1.3.6.1.4.1.25623.1.0.72601");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2012-4199", "CVE-2012-4198", "CVE-2012-4197", "CVE-2012-4189");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-11-26 12:47:33 -0500 (Mon, 26 Nov 2012)");
  script_name("FreeBSD Ports: bugzilla");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: bugzilla

CVE-2012-4199
template/en/default/bug/field-events.js.tmpl in Bugzilla 3.x before
3.6.12, 3.7.x and 4.0.x before 4.0.9, 4.1.x and 4.2.x before 4.2.4,
and 4.3.x and 4.4.x before 4.4rc1 generates JavaScript function calls
containing private product names or private component names in certain
circumstances involving custom-field visibility control, which allows
remote attackers to obtain sensitive information by reading HTML
source code.
CVE-2012-4198
The User.get method in Bugzilla/WebService/User.pm in Bugzilla 3.7.x
and 4.0.x before 4.0.9, 4.1.x and 4.2.x before 4.2.4, and 4.3.x and
4.4.x before 4.4rc1 has a different outcome for a groups request
depending on whether a group exists, which allows remote authenticated
users to discover private group names by observing whether a call
throws an error.
CVE-2012-4197
Bugzilla/Attachment.pm in attachment.cgi in Bugzilla 2.x and 3.x
before 3.6.12, 3.7.x and 4.0.x before 4.0.9, 4.1.x and 4.2.x before
4.2.4, and 4.3.x and 4.4.x before 4.4rc1 allows remote attackers to
read attachment descriptions from private bugs via an obsolete=1
insert action.
CVE-2012-4189
Cross-site scripting (XSS) vulnerability in Bugzilla 4.1.x and 4.2.x
before 4.2.4, and 4.3.x and 4.4.x before 4.4rc1, allows remote
attackers to inject arbitrary web script or HTML via a field value
that is not properly handled during construction of a tabular report,
as demonstrated by the Version field.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=731178");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=781850");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=802204");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=790296");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=808845");
  script_xref(name:"URL", value:"http://yuilibrary.com/support/20121030-vulnerability/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/2b841f88-2e8d-11e2-ad21-20cf30e32f6d.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"3.6.0")>=0 && revcomp(a:bver, b:"3.6.12")<0) {
  txt += "Package bugzilla version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"4.0.0")>=0 && revcomp(a:bver, b:"4.0.9")<0) {
  txt += "Package bugzilla version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"4.2.0")>=0 && revcomp(a:bver, b:"4.2.4")<0) {
  txt += "Package bugzilla version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}