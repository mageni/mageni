###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa_201204_01.nasl 11859 2018-10-12 08:53:01Z cfischer $
#
# Auto generated from Gentoo's XML based advisory
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71311");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4414", "CVE-2011-2300", "CVE-2011-2305", "CVE-2012-0105", "CVE-2012-0111");
  script_version("$Revision: 11859 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-30 07:59:57 -0400 (Mon, 30 Apr 2012)");
  script_name("Gentoo Security Advisory GLSA 201204-01 (virtualbox)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in VirtualBox, allowing local
    attackers to gain escalated privileges.");
  script_tag(name:"solution", value:"All VirtualBox users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-4.1.8'


All VirtualBox binary users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-bin-4.1.8'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201204-01");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=386317");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=399807");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201204-01.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"app-emulation/virtualbox", unaffected: make_list("ge 4.1.8"), vulnerable: make_list("lt 4.1.8"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"app-emulation/virtualbox-bin", unaffected: make_list("ge 4.1.4"), vulnerable: make_list("lt 4.1.8"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
