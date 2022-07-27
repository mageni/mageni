###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa-201603-05.nasl 12128 2018-10-26 13:35:25Z cfischer $
#
# Gentoo Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.fi>
#
# Copyright:
# Copyright (c) 2016 Eero Volotinen, http://solinor.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.121447");
  script_version("$Revision: 12128 $");
  script_tag(name:"creation_date", value:"2016-03-10 07:16:47 +0200 (Thu, 10 Mar 2016)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 15:35:25 +0200 (Fri, 26 Oct 2018) $");
  script_name("Gentoo Security Advisory GLSA 201603-05");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in both LibreOffice and OpenOffice that allow the remote execution of arbitrary code and potential Denial of Service. These vulnerabilities may be exploited through multiple vectors including crafted documents, link handling, printer setup in ODF document types, DOC file formats, and Calc spreadsheets. Please review the referenced CVEs for specific information regarding each.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201603-05");
  script_cve_id("CVE-2014-3524", "CVE-2014-3575", "CVE-2014-3693", "CVE-2014-9093", "CVE-2015-1774", "CVE-2015-4551", "CVE-2015-5212", "CVE-2015-5213", "CVE-2015-5214");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201603-05");
  script_copyright("Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"app-office/libreoffice", unaffected: make_list("ge 4.4.2"), vulnerable: make_list("lt 4.4.2"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-office/libreoffice-bin", unaffected: make_list("ge 4.4.2"), vulnerable: make_list("lt 4.4.2"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-office/libreoffice-bin-debug", unaffected: make_list("ge 4.4.2"), vulnerable: make_list("lt 4.4.2"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-office/openoffice-bin", unaffected: make_list("ge 4.1.2"), vulnerable: make_list("lt 4.1.2"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
