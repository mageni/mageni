###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa_201209_02.nasl 11859 2018-10-12 08:53:01Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.72419");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2347", "CVE-2009-5022", "CVE-2010-1411", "CVE-2010-2065", "CVE-2010-2067", "CVE-2010-2233", "CVE-2010-2443", "CVE-2010-2481", "CVE-2010-2482", "CVE-2010-2483", "CVE-2010-2595", "CVE-2010-2596", "CVE-2010-2597", "CVE-2010-2630", "CVE-2010-2631", "CVE-2010-3087", "CVE-2010-4665", "CVE-2011-0192", "CVE-2011-1167", "CVE-2012-1173", "CVE-2012-2088", "CVE-2012-2113", "CVE-2012-3401");
  script_version("$Revision: 11859 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-09-26 11:20:48 -0400 (Wed, 26 Sep 2012)");
  script_name("Gentoo Security Advisory GLSA 201209-02 (tiff)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in libTIFF could result in execution of
arbitrary code or Denial of Service.");
  script_tag(name:"solution", value:"All libTIFF 4.0 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/tiff-4.0.2-r1'


All libTIFF 3.9 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/tiff-3.9.5-r2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201209-02");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=307001");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=324885");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=357271");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=359871");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=371308");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=410931");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=422673");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=427166");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201209-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"media-libs/tiff", unaffected: make_list("ge 4.0.2-r1", "rge 3.9.5-r2"), vulnerable: make_list("lt 4.0.2-r1"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
