###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1624_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Mozilla SUSE-SU-2014:1624-1 (Mozilla)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850841");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-1587", "CVE-2014-1588", "CVE-2014-1589", "CVE-2014-1590", "CVE-2014-1591", "CVE-2014-1592", "CVE-2014-1593", "CVE-2014-1594", "CVE-2014-1595");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Mozilla SUSE-SU-2014:1624-1 (Mozilla)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox has been updated to the 31.3ESR release fixing bugs and
  security issues.

  *

  MFSA 2014-83 / CVE-2014-1588 / CVE-2014-1587: Mozilla developers and
  community identified and fixed several memory safety bugs in the browser
  engine used in Firefox and other Mozilla-based products. Some
  of these bugs showed evidence of memory corruption under certain
  circumstances, and we presume that with enough effort at least some
  of these could be exploited to run arbitrary code.

  *

  MFSA 2014-85 / CVE-2014-1590: Security researcher Joe Vennix from
  Rapid7 reported that passing a JavaScript object to XMLHttpRequest that
  mimics an input stream will a crash. This crash is not exploitable and can
  only be used for denial of service attacks.

  *

  MFSA 2014-87 / CVE-2014-1592: Security researcher Berend-Jan Wever
  reported a use-after-free created by triggering the creation of a second
  root element while parsing HTML written to a document created with
  document.open(). This leads to a potentially exploitable crash.

  *

  MFSA 2014-88 / CVE-2014-1593: Security researcher Abhishek Arya
  (Inferno) of the Google Chrome Security Team used the Address Sanitizer
  tool to discover a buffer overflow during the parsing of media content.
  This leads to a potentially exploitable crash.

  *

  MFSA 2014-89 / CVE-2014-1594: Security researchers Byoungyoung Lee,
  Chengyu Song, and Taesoo Kim at the Georgia Tech Information Security
  Center (GTISC) reported a bad casting from the BasicThebesLayer to
  BasicContainerLayer, resulting in undefined behavior. This behavior is
  potentially exploitable with some compilers but no clear mechanism to
  trigger it through web content was identified.

  *

  MFSA 2014-90 / CVE-2014-1595: Security researcher Kent Howard
  reported an Apple issue present in OS X 10.10 (Yosemite) where log files
  are created by the CoreGraphics framework of OS X in the /tmp local
  directory. These log files contain a record of all inputs into Mozilla
  programs during their operation. In versions of OS X from versions 10.6
  through 10.9, the CoreGraphics had this logging ability but it was turned
  off by default. In OS X 10.10, this logging was turned on by default for
  some applications that use a custom memory allocator, such as jemalloc,
  because of an initialization bug in the framework. This issue has been
  addressed in Mozilla products by explicitly turning off the framework's
  logging of input events. On vulnerable systems, this issue can result in
  private data such as usernames, passwords, and other inputed data bei ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"Mozilla on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES11.0SP3")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~31.3.0esr~0.8.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~31.3.0esr~0.8.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
