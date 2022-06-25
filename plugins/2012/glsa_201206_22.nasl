###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa_201206_22.nasl 11859 2018-10-12 08:53:01Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.71548");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2906", "CVE-2009-2948", "CVE-2010-0728", "CVE-2010-1635", "CVE-2010-1642", "CVE-2010-2063", "CVE-2010-3069", "CVE-2011-0719", "CVE-2011-1678", "CVE-2011-2724", "CVE-2012-0870", "CVE-2012-1182", "CVE-2012-2111");
  script_version("$Revision: 11859 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:53 -0400 (Fri, 10 Aug 2012)");
  script_name("Gentoo Security Advisory GLSA 201206-22 (Samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in Samba, the worst of
    which may allow execution of arbitrary code with root privileges.");
  script_tag(name:"solution", value:"All Samba users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-fs/samba-3.5.15'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-22");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=290633");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=310105");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=323785");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=332063");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=337295");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=356917");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=382263");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=386375");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=405551");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=411487");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=414319");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201206-22.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"net-fs/samba", unaffected: make_list("ge 3.5.15"), vulnerable: make_list("lt 3.5.15"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
