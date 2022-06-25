###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa_201202_07.nasl 11859 2018-10-12 08:53:01Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.71182");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-1146", "CVE-2011-1486", "CVE-2011-2178", "CVE-2011-2511");
  script_version("$Revision: 11859 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-12 11:35:34 -0400 (Mon, 12 Mar 2012)");
  script_name("Gentoo Security Advisory GLSA 201202-07 (libvirt)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in libvirt, the worst of which
    might allow guest OS users to read arbitrary files on the host OS.");
  script_tag(name:"solution", value:"All libvirt users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/libvirt-0.9.3-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201202-07");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=358877");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=372963");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=373991");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=386287");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201202-07.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"app-emulation/libvirt", unaffected: make_list("ge 0.9.3-r1"), vulnerable: make_list("lt 0.9.3-r1"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
