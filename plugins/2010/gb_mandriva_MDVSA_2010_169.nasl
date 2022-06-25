###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for mozilla-thunderbird MDVSA-2010:169 (mozilla-thunderbird)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "Multiple vulnerabilities has been found and corrected in
  mozilla-thunderbird:

  dom/base/nsJSEnvironment.cpp in Mozilla Firefox 3.5.x before 3.5.11
  and 3.6.x before 3.6.7, Thunderbird 3.0.x before 3.0.6 and 3.1.x
  before 3.1.1, and SeaMonkey before 2.0.6 does not properly suppress
  a script's URL in certain circumstances involving a redirect and an
  error message, which allows remote attackers to obtain sensitive
  information about script parameters via a crafted HTML document,
  related to the window.onerror handler (CVE-2010-2754).

  Mozilla Firefox permits cross-origin loading of CSS stylesheets
  even when the stylesheet download has an incorrect MIME type and the
  stylesheet document is malformed, which allows remote HTTP servers
  to obtain sensitive information via a crafted document (CVE-2010-0654).

  The importScripts Web Worker method in Mozilla Firefox 3.5.x before
  3.5.11 and 3.6.x before 3.6.7, Thunderbird 3.0.x before 3.0.6 and
  3.1.x before 3.1.1, and SeaMonkey before 2.0.6 does not verify that
  content is valid JavaScript code, which allows remote attackers to
  bypass the Same Origin Policy and obtain sensitive information via
  a crafted HTML document (CVE-2010-1213).

  Integer overflow in Mozilla Firefox 3.5.x before 3.5.11 and 3.6.x
  before 3.6.7, Thunderbird 3.0.x before 3.0.6 and 3.1.x before
  3.1.1, and SeaMonkey before 2.0.6 allows remote attackers to execute
  arbitrary code via a large selection attribute in a XUL tree element
  (CVE-2010-2753).

  Integer overflow in an array class in Mozilla Firefox 3.5.x before
  3.5.11 and 3.6.x before 3.6.7, Thunderbird 3.0.x before 3.0.6 and 3.1.x
  before 3.1.1, and SeaMonkey before 2.0.6 allows remote attackers to
  execute arbitrary code by placing many Cascading Style Sheets (CSS)
  values in an array (CVE-2010-2752).

  Multiple unspecified vulnerabilities in the browser engine in Mozilla
  Firefox 3.5.x before 3.5.11 and 3.6.x before 3.6.7, Thunderbird 3.0.x
  before 3.0.6 and 3.1.x before 3.1.1, and SeaMonkey before 2.0.6 allow
  remote attackers to cause a denial of service (memory corruption and
  application crash) or possibly execute arbitrary code via unknown
  vectors (CVE-2010-1211).

  Packages for 2008.0 and 2009.0 are provided as of the Extended
  Maintenance Program. Please visit this link to learn more:
  http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=490

  Additionally, some packages which require so, have been rebuilt and
  are being provided as updates.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "mozilla-thunderbird on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64,
  Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-09/msg00002.php");
  script_oid("1.3.6.1.4.1.25623.1.0.312718");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-07 07:38:40 +0200 (Tue, 07 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2010:169");
  script_cve_id("CVE-2010-2754", "CVE-2010-0654", "CVE-2010-1213", "CVE-2010-2753", "CVE-2010-2752", "CVE-2010-1211");
  script_name("Mandriva Update for mozilla-thunderbird MDVSA-2010:169 (mozilla-thunderbird)");

  script_tag(name: "summary" , value: "Check for the Version of mozilla-thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird", rpm:"mozilla-thunderbird~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-af", rpm:"mozilla-thunderbird-af~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ar", rpm:"mozilla-thunderbird-ar~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-be", rpm:"mozilla-thunderbird-be~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-bg", rpm:"mozilla-thunderbird-bg~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ca", rpm:"mozilla-thunderbird-ca~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-cs", rpm:"mozilla-thunderbird-cs~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-da", rpm:"mozilla-thunderbird-da~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-de", rpm:"mozilla-thunderbird-de~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-el", rpm:"mozilla-thunderbird-el~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-en_GB", rpm:"mozilla-thunderbird-en_GB~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail", rpm:"mozilla-thunderbird-enigmail~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ar", rpm:"mozilla-thunderbird-enigmail-ar~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ca", rpm:"mozilla-thunderbird-enigmail-ca~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-cs", rpm:"mozilla-thunderbird-enigmail-cs~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-de", rpm:"mozilla-thunderbird-enigmail-de~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-el", rpm:"mozilla-thunderbird-enigmail-el~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es", rpm:"mozilla-thunderbird-enigmail-es~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fi", rpm:"mozilla-thunderbird-enigmail-fi~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fr", rpm:"mozilla-thunderbird-enigmail-fr~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-hu", rpm:"mozilla-thunderbird-enigmail-hu~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-it", rpm:"mozilla-thunderbird-enigmail-it~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ja", rpm:"mozilla-thunderbird-enigmail-ja~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ko", rpm:"mozilla-thunderbird-enigmail-ko~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nb", rpm:"mozilla-thunderbird-enigmail-nb~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nl", rpm:"mozilla-thunderbird-enigmail-nl~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pl", rpm:"mozilla-thunderbird-enigmail-pl~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt", rpm:"mozilla-thunderbird-enigmail-pt~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt_BR", rpm:"mozilla-thunderbird-enigmail-pt_BR~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ru", rpm:"mozilla-thunderbird-enigmail-ru~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sl", rpm:"mozilla-thunderbird-enigmail-sl~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sv", rpm:"mozilla-thunderbird-enigmail-sv~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-tr", rpm:"mozilla-thunderbird-enigmail-tr~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_CN", rpm:"mozilla-thunderbird-enigmail-zh_CN~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_TW", rpm:"mozilla-thunderbird-enigmail-zh_TW~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_AR", rpm:"mozilla-thunderbird-es_AR~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_ES", rpm:"mozilla-thunderbird-es_ES~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et", rpm:"mozilla-thunderbird-et~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et_EE", rpm:"mozilla-thunderbird-et_EE~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-eu", rpm:"mozilla-thunderbird-eu~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fi", rpm:"mozilla-thunderbird-fi~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fr", rpm:"mozilla-thunderbird-fr~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fy", rpm:"mozilla-thunderbird-fy~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ga", rpm:"mozilla-thunderbird-ga~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-gl", rpm:"mozilla-thunderbird-gl~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-he", rpm:"mozilla-thunderbird-he~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-hu", rpm:"mozilla-thunderbird-hu~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-id", rpm:"mozilla-thunderbird-id~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-is", rpm:"mozilla-thunderbird-is~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-it", rpm:"mozilla-thunderbird-it~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ja", rpm:"mozilla-thunderbird-ja~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ka", rpm:"mozilla-thunderbird-ka~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ko", rpm:"mozilla-thunderbird-ko~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-lt", rpm:"mozilla-thunderbird-lt~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nb_NO", rpm:"mozilla-thunderbird-nb_NO~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nl", rpm:"mozilla-thunderbird-nl~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nn_NO", rpm:"mozilla-thunderbird-nn_NO~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pa_IN", rpm:"mozilla-thunderbird-pa_IN~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pl", rpm:"mozilla-thunderbird-pl~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_BR", rpm:"mozilla-thunderbird-pt_BR~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_PT", rpm:"mozilla-thunderbird-pt_PT~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ro", rpm:"mozilla-thunderbird-ro~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ru", rpm:"mozilla-thunderbird-ru~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-si", rpm:"mozilla-thunderbird-si~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sk", rpm:"mozilla-thunderbird-sk~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sq", rpm:"mozilla-thunderbird-sq~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sr", rpm:"mozilla-thunderbird-sr~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sv_SE", rpm:"mozilla-thunderbird-sv_SE~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-tr", rpm:"mozilla-thunderbird-tr~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-uk", rpm:"mozilla-thunderbird-uk~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-vi", rpm:"mozilla-thunderbird-vi~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_CN", rpm:"mozilla-thunderbird-zh_CN~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_TW", rpm:"mozilla-thunderbird-zh_TW~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nsinstall", rpm:"nsinstall~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-l10n", rpm:"mozilla-thunderbird-enigmail-l10n~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-l10n", rpm:"mozilla-thunderbird-l10n~3.0.6~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"beagle", rpm:"beagle~0.3.9~20.13mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-crawl-system", rpm:"beagle-crawl-system~0.3.9~20.13mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-doc", rpm:"beagle-doc~0.3.9~20.13mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-evolution", rpm:"beagle-evolution~0.3.9~20.13mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-gui", rpm:"beagle-gui~0.3.9~20.13mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-gui-qt", rpm:"beagle-gui-qt~0.3.9~20.13mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-libs", rpm:"beagle-libs~0.3.9~20.13mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ext-beagle", rpm:"firefox-ext-beagle~0.3.9~20.13mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird", rpm:"mozilla-thunderbird~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-af", rpm:"mozilla-thunderbird-af~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ar", rpm:"mozilla-thunderbird-ar~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-be", rpm:"mozilla-thunderbird-be~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-beagle", rpm:"mozilla-thunderbird-beagle~0.3.9~20.13mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-bg", rpm:"mozilla-thunderbird-bg~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ca", rpm:"mozilla-thunderbird-ca~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-cs", rpm:"mozilla-thunderbird-cs~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-da", rpm:"mozilla-thunderbird-da~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-de", rpm:"mozilla-thunderbird-de~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-el", rpm:"mozilla-thunderbird-el~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-en_GB", rpm:"mozilla-thunderbird-en_GB~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail", rpm:"mozilla-thunderbird-enigmail~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ar", rpm:"mozilla-thunderbird-enigmail-ar~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ca", rpm:"mozilla-thunderbird-enigmail-ca~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-cs", rpm:"mozilla-thunderbird-enigmail-cs~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-de", rpm:"mozilla-thunderbird-enigmail-de~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-el", rpm:"mozilla-thunderbird-enigmail-el~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es", rpm:"mozilla-thunderbird-enigmail-es~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fi", rpm:"mozilla-thunderbird-enigmail-fi~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fr", rpm:"mozilla-thunderbird-enigmail-fr~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-hu", rpm:"mozilla-thunderbird-enigmail-hu~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-it", rpm:"mozilla-thunderbird-enigmail-it~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ja", rpm:"mozilla-thunderbird-enigmail-ja~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ko", rpm:"mozilla-thunderbird-enigmail-ko~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nb", rpm:"mozilla-thunderbird-enigmail-nb~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nl", rpm:"mozilla-thunderbird-enigmail-nl~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pl", rpm:"mozilla-thunderbird-enigmail-pl~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt", rpm:"mozilla-thunderbird-enigmail-pt~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt_BR", rpm:"mozilla-thunderbird-enigmail-pt_BR~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ru", rpm:"mozilla-thunderbird-enigmail-ru~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sl", rpm:"mozilla-thunderbird-enigmail-sl~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sv", rpm:"mozilla-thunderbird-enigmail-sv~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-tr", rpm:"mozilla-thunderbird-enigmail-tr~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_CN", rpm:"mozilla-thunderbird-enigmail-zh_CN~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_TW", rpm:"mozilla-thunderbird-enigmail-zh_TW~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_AR", rpm:"mozilla-thunderbird-es_AR~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_ES", rpm:"mozilla-thunderbird-es_ES~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et", rpm:"mozilla-thunderbird-et~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et_EE", rpm:"mozilla-thunderbird-et_EE~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-eu", rpm:"mozilla-thunderbird-eu~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fi", rpm:"mozilla-thunderbird-fi~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fr", rpm:"mozilla-thunderbird-fr~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fy", rpm:"mozilla-thunderbird-fy~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ga", rpm:"mozilla-thunderbird-ga~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-gl", rpm:"mozilla-thunderbird-gl~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-he", rpm:"mozilla-thunderbird-he~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-hu", rpm:"mozilla-thunderbird-hu~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-id", rpm:"mozilla-thunderbird-id~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-is", rpm:"mozilla-thunderbird-is~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-it", rpm:"mozilla-thunderbird-it~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ja", rpm:"mozilla-thunderbird-ja~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ka", rpm:"mozilla-thunderbird-ka~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ko", rpm:"mozilla-thunderbird-ko~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-lt", rpm:"mozilla-thunderbird-lt~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nb_NO", rpm:"mozilla-thunderbird-nb_NO~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nl", rpm:"mozilla-thunderbird-nl~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nn_NO", rpm:"mozilla-thunderbird-nn_NO~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pa_IN", rpm:"mozilla-thunderbird-pa_IN~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pl", rpm:"mozilla-thunderbird-pl~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_BR", rpm:"mozilla-thunderbird-pt_BR~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_PT", rpm:"mozilla-thunderbird-pt_PT~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ro", rpm:"mozilla-thunderbird-ro~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ru", rpm:"mozilla-thunderbird-ru~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-si", rpm:"mozilla-thunderbird-si~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sk", rpm:"mozilla-thunderbird-sk~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sq", rpm:"mozilla-thunderbird-sq~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sr", rpm:"mozilla-thunderbird-sr~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sv_SE", rpm:"mozilla-thunderbird-sv_SE~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-tr", rpm:"mozilla-thunderbird-tr~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-uk", rpm:"mozilla-thunderbird-uk~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-vi", rpm:"mozilla-thunderbird-vi~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_CN", rpm:"mozilla-thunderbird-zh_CN~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_TW", rpm:"mozilla-thunderbird-zh_TW~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nsinstall", rpm:"nsinstall~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-l10n", rpm:"mozilla-thunderbird-enigmail-l10n~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-l10n", rpm:"mozilla-thunderbird-l10n~3.0.6~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"beagle", rpm:"beagle~0.3.8~13.25mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-crawl-system", rpm:"beagle-crawl-system~0.3.8~13.25mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-doc", rpm:"beagle-doc~0.3.8~13.25mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-epiphany", rpm:"beagle-epiphany~0.3.8~13.25mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-evolution", rpm:"beagle-evolution~0.3.8~13.25mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-gui", rpm:"beagle-gui~0.3.8~13.25mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-gui-qt", rpm:"beagle-gui-qt~0.3.8~13.25mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-libs", rpm:"beagle-libs~0.3.8~13.25mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ext-beagle", rpm:"firefox-ext-beagle~0.3.8~13.25mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird", rpm:"mozilla-thunderbird~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-af", rpm:"mozilla-thunderbird-af~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ar", rpm:"mozilla-thunderbird-ar~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-be", rpm:"mozilla-thunderbird-be~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-beagle", rpm:"mozilla-thunderbird-beagle~0.3.8~13.23mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-beagle", rpm:"mozilla-thunderbird-beagle~0.3.8~13.25mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-bg", rpm:"mozilla-thunderbird-bg~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ca", rpm:"mozilla-thunderbird-ca~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-cs", rpm:"mozilla-thunderbird-cs~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-da", rpm:"mozilla-thunderbird-da~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-de", rpm:"mozilla-thunderbird-de~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-el", rpm:"mozilla-thunderbird-el~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-en_GB", rpm:"mozilla-thunderbird-en_GB~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail", rpm:"mozilla-thunderbird-enigmail~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ar", rpm:"mozilla-thunderbird-enigmail-ar~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ca", rpm:"mozilla-thunderbird-enigmail-ca~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-cs", rpm:"mozilla-thunderbird-enigmail-cs~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-de", rpm:"mozilla-thunderbird-enigmail-de~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-el", rpm:"mozilla-thunderbird-enigmail-el~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es", rpm:"mozilla-thunderbird-enigmail-es~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fi", rpm:"mozilla-thunderbird-enigmail-fi~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fr", rpm:"mozilla-thunderbird-enigmail-fr~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-hu", rpm:"mozilla-thunderbird-enigmail-hu~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-it", rpm:"mozilla-thunderbird-enigmail-it~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ja", rpm:"mozilla-thunderbird-enigmail-ja~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ko", rpm:"mozilla-thunderbird-enigmail-ko~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nb", rpm:"mozilla-thunderbird-enigmail-nb~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nl", rpm:"mozilla-thunderbird-enigmail-nl~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pl", rpm:"mozilla-thunderbird-enigmail-pl~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt", rpm:"mozilla-thunderbird-enigmail-pt~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt_BR", rpm:"mozilla-thunderbird-enigmail-pt_BR~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ru", rpm:"mozilla-thunderbird-enigmail-ru~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sl", rpm:"mozilla-thunderbird-enigmail-sl~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sv", rpm:"mozilla-thunderbird-enigmail-sv~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-tr", rpm:"mozilla-thunderbird-enigmail-tr~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_CN", rpm:"mozilla-thunderbird-enigmail-zh_CN~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_TW", rpm:"mozilla-thunderbird-enigmail-zh_TW~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_AR", rpm:"mozilla-thunderbird-es_AR~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_ES", rpm:"mozilla-thunderbird-es_ES~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et", rpm:"mozilla-thunderbird-et~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et_EE", rpm:"mozilla-thunderbird-et_EE~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-eu", rpm:"mozilla-thunderbird-eu~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fi", rpm:"mozilla-thunderbird-fi~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fr", rpm:"mozilla-thunderbird-fr~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fy", rpm:"mozilla-thunderbird-fy~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ga", rpm:"mozilla-thunderbird-ga~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-gl", rpm:"mozilla-thunderbird-gl~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-he", rpm:"mozilla-thunderbird-he~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-hu", rpm:"mozilla-thunderbird-hu~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-id", rpm:"mozilla-thunderbird-id~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-is", rpm:"mozilla-thunderbird-is~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-it", rpm:"mozilla-thunderbird-it~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ja", rpm:"mozilla-thunderbird-ja~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ka", rpm:"mozilla-thunderbird-ka~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ko", rpm:"mozilla-thunderbird-ko~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-lt", rpm:"mozilla-thunderbird-lt~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nb_NO", rpm:"mozilla-thunderbird-nb_NO~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nl", rpm:"mozilla-thunderbird-nl~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nn_NO", rpm:"mozilla-thunderbird-nn_NO~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pa_IN", rpm:"mozilla-thunderbird-pa_IN~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pl", rpm:"mozilla-thunderbird-pl~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_BR", rpm:"mozilla-thunderbird-pt_BR~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_PT", rpm:"mozilla-thunderbird-pt_PT~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ro", rpm:"mozilla-thunderbird-ro~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ru", rpm:"mozilla-thunderbird-ru~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-si", rpm:"mozilla-thunderbird-si~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sk", rpm:"mozilla-thunderbird-sk~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sq", rpm:"mozilla-thunderbird-sq~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sr", rpm:"mozilla-thunderbird-sr~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sv_SE", rpm:"mozilla-thunderbird-sv_SE~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-tr", rpm:"mozilla-thunderbird-tr~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-uk", rpm:"mozilla-thunderbird-uk~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-vi", rpm:"mozilla-thunderbird-vi~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_CN", rpm:"mozilla-thunderbird-zh_CN~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_TW", rpm:"mozilla-thunderbird-zh_TW~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nsinstall", rpm:"nsinstall~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-l10n", rpm:"mozilla-thunderbird-enigmail-l10n~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-l10n", rpm:"mozilla-thunderbird-l10n~3.0.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
