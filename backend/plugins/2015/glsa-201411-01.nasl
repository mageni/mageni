###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa-201411-01.nasl 12128 2018-10-26 13:35:25Z cfischer $
#
# Gentoo Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121276");
  script_version("$Revision: 12128 $");
  script_tag(name:"creation_date", value:"2015-09-29 11:27:56 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 15:35:25 +0200 (Fri, 26 Oct 2018) $");
  script_name("Gentoo Security Advisory GLSA 201411-01");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in VLC. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201411-01");
  script_cve_id("CVE-2010-1441", "CVE-2010-1442", "CVE-2010-1443", "CVE-2010-1444", "CVE-2010-1445", "CVE-2010-2062", "CVE-2010-2937", "CVE-2010-3124", "CVE-2010-3275", "CVE-2010-3276", "CVE-2010-3907", "CVE-2011-0021", "CVE-2011-0522", "CVE-2011-0531", "CVE-2011-1087", "CVE-2011-1684", "CVE-2011-2194", "CVE-2011-2587", "CVE-2011-2588", "CVE-2011-3623", "CVE-2012-0023", "CVE-2012-1775", "CVE-2012-1776", "CVE-2012-2396", "CVE-2012-3377", "CVE-2012-5470", "CVE-2012-5855", "CVE-2013-1868", "CVE-2013-1954", "CVE-2013-3245", "CVE-2013-4388", "CVE-2013-6283", "CVE-2013-6934");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201411-01");
  script_copyright("Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"media-video/vlc", unaffected: make_list("ge 2.1.2"), vulnerable: make_list("lt 2.1.2"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
