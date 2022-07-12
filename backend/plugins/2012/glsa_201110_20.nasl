###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa_201110_20.nasl 11859 2018-10-12 08:53:01Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.70783");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0405", "CVE-2010-3434", "CVE-2010-4260", "CVE-2010-4261", "CVE-2010-4479", "CVE-2011-1003", "CVE-2011-2721", "CVE-2011-3627");
  script_version("$Revision: 11859 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:40 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201110-20 (Clam AntiVirus)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in Clam AntiVirus, the most
    severe of which may allow the execution of arbitrary code.");
  script_tag(name:"solution", value:"All Clam AntiVirus users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-antivirus/clamav-0.97.3'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-20");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=338226");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=347627");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=354019");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=378815");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=387521");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201110-20.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"app-antivirus/clamav", unaffected: make_list("ge 0.97.3"), vulnerable: make_list("lt 0.97.3"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
