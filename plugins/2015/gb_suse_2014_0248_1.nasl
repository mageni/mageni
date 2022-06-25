###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0248_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for MozillaFirefox SUSE-SU-2014:0248-1 (MozillaFirefox)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850809");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-1477", "CVE-2014-1479", "CVE-2014-1480", "CVE-2014-1481",
                "CVE-2014-1482", "CVE-2014-1483", "CVE-2014-1484", "CVE-2014-1485",
                "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1488", "CVE-2014-1489",
                "CVE-2014-1490", "CVE-2014-1491");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaFirefox SUSE-SU-2014:0248-1 (MozillaFirefox)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This updates the Mozilla Firefox browser to the 24.3.0ESR
  security release.  The Mozilla NSS libraries are now on
  version 3.15.4.

  The following security issues have been fixed:

  *

  MFSA 2014-01: Memory safety bugs fixed in Firefox ESR
  24.3 and Firefox 27.0 (CVE-2014-1477)(bnc#862345)

  *

  MFSA 2014-02: Using XBL scopes its possible to
  steal(clone) native anonymous content
  (CVE-2014-1479)(bnc#862348)

  *

  MFSA 2014-03: Download 'open file' dialog delay is
  too quick, doesn't prevent clickjacking (CVE-2014-1480)

  *

  MFSA 2014-04: Image decoding causing FireFox to crash
  with Goo Create (CVE-2014-1482)(bnc#862356)

  *

  MFSA 2014-05: caretPositionFromPoint and
  elementFromPoint leak information about iframe contents via
  timing information (CVE-2014-1483)(bnc#862360)

  *

  MFSA 2014-06: Fennec leaks profile path to logcat
  (CVE-2014-1484)

  *

  MFSA 2014-07: CSP should block XSLT as script, not as
  style (CVE-2014-1485)

  *

  MFSA 2014-08: imgRequestProxy Use-After-Free Remote
  Code Execution Vulnerability (CVE-2014-1486)

  *

  MFSA 2014-09: Cross-origin information disclosure
  with error message of Web Workers (CVE-2014-1487)

  *

  MFSA 2014-10: settings &amp  history ID bug
  (CVE-2014-1489)

  *

  MFSA 2014-11: Firefox reproducibly crashes when using
  asm.js code in workers and transferable objects
  (CVE-2014-1488)

  *

  MFSA 2014-12: TOCTOU, potential use-after-free in
  libssl's session ticket processing
  (CVE-2014-1490)(bnc#862300) Do not allow p-1 as a public DH
  value (CVE-2014-1491)(bnc#862289)

  *

  MFSA 2014-13: Inconsistent this value when invoking
  getters on window (CVE-2014-1481)(bnc#862309)

  Security Issue references:

  * CVE-2014-1477

  * CVE-2014-1479

  * CVE-2014-1480

  * CVE-2014-1481

  * CVE-2014-1482

  * CVE-2014-1483
  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"MozillaFirefox on SUSE Linux Enterprise Server 11 SP3");
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

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~24.3.0esr~0.8.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED-24", rpm:"MozillaFirefox-branding-SLED-24~0.7.14", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~24.3.0esr~0.8.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.15.4~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.15.4~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.15.4~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.15.4~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.15.4~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.15.4~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.15.4~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-x86", rpm:"libfreebl3-x86~3.15.4~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-x86", rpm:"libsoftokn3-x86~3.15.4~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-x86", rpm:"mozilla-nss-x86~3.15.4~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
