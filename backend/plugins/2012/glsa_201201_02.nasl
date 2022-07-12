###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa_201201_02.nasl 11859 2018-10-12 08:53:01Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.70803");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2008-3963", "CVE-2008-4097", "CVE-2008-4098", "CVE-2008-4456", "CVE-2008-7247", "CVE-2009-2446", "CVE-2009-4019", "CVE-2009-4028", "CVE-2009-4484", "CVE-2010-1621", "CVE-2010-1626", "CVE-2010-1848", "CVE-2010-1849", "CVE-2010-1850", "CVE-2010-2008", "CVE-2010-3676", "CVE-2010-3677", "CVE-2010-3678", "CVE-2010-3679", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3683", "CVE-2010-3833", "CVE-2010-3834", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840");
  script_version("$Revision: 11859 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:41 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201201-02 (MySQL)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in MySQL, some of which may
    allow execution of arbitrary code.");
  script_tag(name:"solution", value:"All MySQL users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/mysql-5.1.56'


NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since May 14, 2011. It is likely that your system is
already no
      longer affected by this issue.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201201-02");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=220813");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=229329");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=237166");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=238117");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=240407");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=277717");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=294187");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=303747");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=319489");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=321791");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=339717");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=344987");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=351413");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201201-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"dev-db/mysql", unaffected: make_list("ge 5.1.56"), vulnerable: make_list("lt 5.1.56"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
