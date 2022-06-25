###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa-201309-16.nasl 12128 2018-10-26 13:35:25Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.121030");
  script_version("$Revision: 12128 $");
  script_tag(name:"creation_date", value:"2015-09-29 11:25:53 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 15:35:25 +0200 (Fri, 26 Oct 2018) $");
  script_name("Gentoo Security Advisory GLSA 201309-16");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Chromium and V8. Please review the CVE identifiers and release notes referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201309-16");
  script_cve_id("CVE-2012-5116", "CVE-2012-5117", "CVE-2012-5118", "CVE-2012-5120", "CVE-2012-5121", "CVE-2012-5122", "CVE-2012-5123", "CVE-2012-5124", "CVE-2012-5125", "CVE-2012-5126", "CVE-2012-5127", "CVE-2012-5128", "CVE-2012-5130", "CVE-2012-5132", "CVE-2012-5133", "CVE-2012-5135", "CVE-2012-5136", "CVE-2012-5137", "CVE-2012-5138", "CVE-2012-5139", "CVE-2012-5140", "CVE-2012-5141", "CVE-2012-5142", "CVE-2012-5143", "CVE-2012-5144", "CVE-2012-5145", "CVE-2012-5146", "CVE-2012-5147", "CVE-2012-5148", "CVE-2012-5149", "CVE-2012-5150", "CVE-2012-5151", "CVE-2012-5152", "CVE-2012-5153", "CVE-2012-5154", "CVE-2013-0828", "CVE-2013-0829", "CVE-2013-0830", "CVE-2013-0831", "CVE-2013-0832", "CVE-2013-0833", "CVE-2013-0834", "CVE-2013-0835", "CVE-2013-0836", "CVE-2013-0837", "CVE-2013-0838", "CVE-2013-0839", "CVE-2013-0840", "CVE-2013-0841", "CVE-2013-0842", "CVE-2013-0879", "CVE-2013-0880", "CVE-2013-0881", "CVE-2013-0882", "CVE-2013-0883", "CVE-2013-0884", "CVE-2013-0885", "CVE-2013-0887", "CVE-2013-0888", "CVE-2013-0889", "CVE-2013-0890", "CVE-2013-0891", "CVE-2013-0892", "CVE-2013-0893", "CVE-2013-0894", "CVE-2013-0895", "CVE-2013-0896", "CVE-2013-0897", "CVE-2013-0898", "CVE-2013-0899", "CVE-2013-0900", "CVE-2013-0902", "CVE-2013-0903", "CVE-2013-0904", "CVE-2013-0905", "CVE-2013-0906", "CVE-2013-0907", "CVE-2013-0908", "CVE-2013-0909", "CVE-2013-0910", "CVE-2013-0911", "CVE-2013-0912", "CVE-2013-0916", "CVE-2013-0917", "CVE-2013-0918", "CVE-2013-0919", "CVE-2013-0920", "CVE-2013-0921", "CVE-2013-0922", "CVE-2013-0923", "CVE-2013-0924", "CVE-2013-0925", "CVE-2013-0926", "CVE-2013-2836", "CVE-2013-2837", "CVE-2013-2838", "CVE-2013-2839", "CVE-2013-2840", "CVE-2013-2841", "CVE-2013-2842", "CVE-2013-2843", "CVE-2013-2844", "CVE-2013-2845", "CVE-2013-2846", "CVE-2013-2847", "CVE-2013-2848", "CVE-2013-2849", "CVE-2013-2853", "CVE-2013-2855", "CVE-2013-2856", "CVE-2013-2857", "CVE-2013-2858", "CVE-2013-2859", "CVE-2013-2860", "CVE-2013-2861", "CVE-2013-2862", "CVE-2013-2863", "CVE-2013-2865", "CVE-2013-2867", "CVE-2013-2868", "CVE-2013-2869", "CVE-2013-2870", "CVE-2013-2871", "CVE-2013-2874", "CVE-2013-2875", "CVE-2013-2876", "CVE-2013-2877", "CVE-2013-2878", "CVE-2013-2879", "CVE-2013-2880", "CVE-2013-2881", "CVE-2013-2882", "CVE-2013-2883", "CVE-2013-2884", "CVE-2013-2885", "CVE-2013-2886", "CVE-2013-2887", "CVE-2013-2900", "CVE-2013-2901", "CVE-2013-2902", "CVE-2013-2903", "CVE-2013-2904", "CVE-2013-2905");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201309-16");
  script_copyright("Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"www-client/chromium", unaffected: make_list("ge 29.0.1457.57"), vulnerable: make_list("lt 29.0.1457.57"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-lang/v8", unaffected: make_list("ge 3.18.5.14"), vulnerable: make_list("lt 3.18.5.14"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
