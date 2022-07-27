###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for mozilla MDVSA-2012:110-1 (mozilla)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:110-1");
  script_oid("1.3.6.1.4.1.25623.1.0.831708");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-08-03 11:18:18 +0530 (Fri, 03 Aug 2012)");
  script_cve_id("CVE-2012-1949", "CVE-2012-1948", "CVE-2012-1950", "CVE-2012-1951",
                "CVE-2012-1954", "CVE-2012-1953", "CVE-2012-1952", "CVE-2012-1955",
                "CVE-2012-1966", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959",
                "CVE-2012-1960", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963",
                "CVE-2012-1964", "CVE-2012-1965", "CVE-2012-1967");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandriva Update for mozilla MDVSA-2012:110-1 (mozilla)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2011\.0");
  script_tag(name:"affected", value:"mozilla on Mandriva Linux 2011.0");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Security issues were identified and fixed in mozilla firefox and
  thunderbird:

  Mozilla developers identified and fixed several memory safety
  bugs in the browser engine used in Firefox and other Mozilla-based
  products. Some of these bugs showed evidence of memory corruption
  under certain circumstances, and we presume that with enough effort
  at least some of these could be exploited to run arbitrary code
  (CVE-2012-1949, CVE-2012-1948).

  Security researcher Mario Gomes andresearch firm Code Audit Labs
  reported a mechanism to short-circuit page loads through drag and drop
  to the addressbar by canceling the page load. This causes the address
  of the previously site entered to be displayed in the addressbar
  instead of the currently loaded page. This could lead to potential
  phishing attacks on users (CVE-2012-1950).

  Google security researcher Abhishek Arya used the Address Sanitizer
  tool to uncover four issues: two use-after-free problems, one out of
  bounds read bug, and a bad cast. The first use-after-free problem is
  caused when an array of nsSMILTimeValueSpec objects is destroyed but
  attempts are made to call into objects in this array later. The second
  use-after-free problem is in nsDocument::AdoptNode when it adopts into
  an empty document and then adopts into another document, emptying the
  first one. The heap buffer overflow is in ElementAnimations when data
  is read off of end of an array and then pointers are dereferenced. The
  bad cast happens when nsTableFrame::InsertFrames is called with
  frames in aFrameList that are a mix of row group frames and column
  group frames. AppendFrames is not able to handle this mix. All four of
  these issues are potentially exploitable (CVE-2012-1951, CVE-2012-1954,
  CVE-2012-1953, CVE-2012-1952).

  Security researcher Mariusz Mlynski reported an issue with spoofing
  of the location property. In this issue, calls to history.forward
  and history.back are used to navigate to a site while displaying the
  previous site in the addressbar but changing the baseURI to the newer
  site. This can be used for phishing by allowing the user input form
  or other data on the newer, attacking, site while appearing to be on
  the older, displayed site (CVE-2012-1955).

  Mozilla security researcher moz_bug_r_a4 reported a cross-site
  scripting (XSS) attack through the context menu using a data: URL. In
  this issue, context menu functionality (View Image, Show only this
  frame, and View background image) are disallowed in a javascript:
  URL but allowed in a data: URL, allowing for XSS. This can lead to
 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"firefox-af", rpm:"firefox-af~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ar", rpm:"firefox-ar~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ast", rpm:"firefox-ast~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-be", rpm:"firefox-be~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-bg", rpm:"firefox-bg~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-bn_BD", rpm:"firefox-bn_BD~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-bn_IN", rpm:"firefox-bn_IN~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-br", rpm:"firefox-br~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-bs", rpm:"firefox-bs~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ca", rpm:"firefox-ca~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-cs", rpm:"firefox-cs~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-cy", rpm:"firefox-cy~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-da", rpm:"firefox-da~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-de", rpm:"firefox-de~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-el", rpm:"firefox-el~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-en_GB", rpm:"firefox-en_GB~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-en_ZA", rpm:"firefox-en_ZA~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-eo", rpm:"firefox-eo~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-es_AR", rpm:"firefox-es_AR~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-es_CL", rpm:"firefox-es_CL~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-es_ES", rpm:"firefox-es_ES~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-es_MX", rpm:"firefox-es_MX~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-et", rpm:"firefox-et~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-eu", rpm:"firefox-eu~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-fa", rpm:"firefox-fa~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-fi", rpm:"firefox-fi~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-fr", rpm:"firefox-fr~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-fy", rpm:"firefox-fy~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ga_IE", rpm:"firefox-ga_IE~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-gd", rpm:"firefox-gd~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-gl", rpm:"firefox-gl~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-gu_IN", rpm:"firefox-gu_IN~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-he", rpm:"firefox-he~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-hi", rpm:"firefox-hi~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-hr", rpm:"firefox-hr~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-hu", rpm:"firefox-hu~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-hy", rpm:"firefox-hy~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-id", rpm:"firefox-id~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-is", rpm:"firefox-is~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-it", rpm:"firefox-it~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ja", rpm:"firefox-ja~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-kk", rpm:"firefox-kk~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-kn", rpm:"firefox-kn~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ko", rpm:"firefox-ko~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ku", rpm:"firefox-ku~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-lg", rpm:"firefox-lg~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-lt", rpm:"firefox-lt~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-lv", rpm:"firefox-lv~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-mai", rpm:"firefox-mai~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-mk", rpm:"firefox-mk~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ml", rpm:"firefox-ml~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-mr", rpm:"firefox-mr~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-nb_NO", rpm:"firefox-nb_NO~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-nl", rpm:"firefox-nl~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-nn_NO", rpm:"firefox-nn_NO~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-nso", rpm:"firefox-nso~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-or", rpm:"firefox-or~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-pa_IN", rpm:"firefox-pa_IN~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-pl", rpm:"firefox-pl~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-pt_BR", rpm:"firefox-pt_BR~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-pt_PT", rpm:"firefox-pt_PT~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ro", rpm:"firefox-ro~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ru", rpm:"firefox-ru~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-si", rpm:"firefox-si~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-sk", rpm:"firefox-sk~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-sl", rpm:"firefox-sl~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-sq", rpm:"firefox-sq~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-sr", rpm:"firefox-sr~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-sv_SE", rpm:"firefox-sv_SE~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ta", rpm:"firefox-ta~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ta_LK", rpm:"firefox-ta_LK~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-te", rpm:"firefox-te~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-th", rpm:"firefox-th~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-tr", rpm:"firefox-tr~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-uk", rpm:"firefox-uk~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-vi", rpm:"firefox-vi~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-zh_CN", rpm:"firefox-zh_CN~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-zh_TW", rpm:"firefox-zh_TW~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-zu", rpm:"firefox-zu~14.0.1~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
