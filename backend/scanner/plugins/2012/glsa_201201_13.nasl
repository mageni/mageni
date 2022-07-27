###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa_201201_13.nasl 11859 2018-10-12 08:53:01Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.70814");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3295", "CVE-2009-4212", "CVE-2010-0283", "CVE-2010-0629", "CVE-2010-1320", "CVE-2010-1321", "CVE-2010-1322", "CVE-2010-1323", "CVE-2010-1324", "CVE-2010-4020", "CVE-2010-4021", "CVE-2010-4022", "CVE-2011-0281", "CVE-2011-0282", "CVE-2011-0283", "CVE-2011-0284", "CVE-2011-0285", "CVE-2011-1527", "CVE-2011-1528", "CVE-2011-1529", "CVE-2011-1530", "CVE-2011-4151");
  script_version("$Revision: 11859 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:42 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201201-13 (mit-krb5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in MIT Kerberos 5, the
    most severe of which may allow remote execution of arbitrary code.");
  script_tag(name:"solution", value:"All MIT Kerberos 5 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-crypt/mit-krb5-1.9.2-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201201-13");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=303723");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=308021");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=321935");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=323525");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=339866");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=347369");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=352859");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=359129");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=363507");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=387585");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=393429");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201201-13.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"app-crypt/mit-krb5", unaffected: make_list("ge 1.9.2-r1"), vulnerable: make_list("lt 1.9.2-r1"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
