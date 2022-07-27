###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa_201101_09.nasl 14171 2019-03-14 10:22:03Z cfischer $
#
# Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.69045");
  script_version("$Revision: 14171 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 11:22:03 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4546", "CVE-2009-3793", "CVE-2010-0186", "CVE-2010-0187", "CVE-2010-0209", "CVE-2010-1297", "CVE-2010-2160", "CVE-2010-2161", "CVE-2010-2162", "CVE-2010-2163", "CVE-2010-2164", "CVE-2010-2165", "CVE-2010-2166", "CVE-2010-2167", "CVE-2010-2169", "CVE-2010-2170", "CVE-2010-2171", "CVE-2010-2172", "CVE-2010-2173", "CVE-2010-2174", "CVE-2010-2175", "CVE-2010-2176", "CVE-2010-2177", "CVE-2010-2178", "CVE-2010-2179", "CVE-2010-2180", "CVE-2010-2181", "CVE-2010-2182", "CVE-2010-2183", "CVE-2010-2184", "CVE-2010-2185", "CVE-2010-2186", "CVE-2010-2187", "CVE-2010-2188", "CVE-2010-2189", "CVE-2010-2213", "CVE-2010-2214", "CVE-2010-2215", "CVE-2010-2216", "CVE-2010-2884", "CVE-2010-3636", "CVE-2010-3639", "CVE-2010-3640", "CVE-2010-3641", "CVE-2010-3642", "CVE-2010-3643", "CVE-2010-3644", "CVE-2010-3645", "CVE-2010-3646", "CVE-2010-3647", "CVE-2010-3648", "CVE-2010-3649", "CVE-2010-3650", "CVE-2010-3652", "CVE-2010-3654", "CVE-2010-3976");
  script_name("Gentoo Security Advisory GLSA 201101-09 (adobe-flash)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in Adobe Flash Player might allow remote attackers
    to execute arbitrary code or cause a Denial of Service.");
  script_tag(name:"solution", value:"All Adobe Flash Player users should upgrade to the latest stable
    version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-plugins/adobe-flash-10.1.102.64'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201101-09");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=307749");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=322855");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=332205");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=337204");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=343089");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-06.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-14.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-16.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-22.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-26.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201101-09.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-plugins/adobe-flash", unaffected: make_list("ge 10.1.102.64"), vulnerable: make_list("lt 10.1.102.64"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
