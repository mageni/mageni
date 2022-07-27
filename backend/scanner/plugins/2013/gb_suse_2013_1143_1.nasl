###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2013_1143_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for xulrunner openSUSE-SU-2013:1143-1 (xulrunner)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850496");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-11-19 14:05:54 +0530 (Tue, 19 Nov 2013)");
  script_cve_id("CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686",
                "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693",
                "CVE-2013-1694", "CVE-2013-1697");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for xulrunner openSUSE-SU-2013:1143-1 (xulrunner)");
  script_tag(name:"affected", value:"xulrunner on openSUSE 12.2");
  script_tag(name:"insight", value:"Mozilla xulrunner was update to 17.0.7esr (bnc#825935)

  Security issues fixed:

  * MFSA 2013-49/CVE-2013-1682 Miscellaneous memory safety
  hazards

  * MFSA 2013-50/CVE-2013-1684/CVE-2013-1685/CVE-2013-1686
  Memory corruption found using Address Sanitizer

  * MFSA 2013-51/CVE-2013-1687 (bmo#863933, bmo#866823)
  Privileged content access and execution via XBL

  * MFSA 2013-53/CVE-2013-1690 (bmo#857883) Execution of
  unmapped memory through onreadystatechange event

  * MFSA 2013-54/CVE-2013-1692 (bmo#866915) Data in the
  body of XHR HEAD requests leads to CSRF attacks

  * MFSA 2013-55/CVE-2013-1693 (bmo#711043) SVG filters can
  lead to information disclosure

  * MFSA 2013-56/CVE-2013-1694 (bmo#848535) PreserveWrapper
  has inconsistent behavior

  * MFSA 2013-59/CVE-2013-1697 (bmo#858101) XrayWrappers
  can be bypassed to run user defined methods in a
  privileged context");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xulrunner'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.2");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.2")
{

  if ((res = isrpmvuln(pkg:"mozilla-js", rpm:"mozilla-js~17.0.7~2.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js-debuginfo", rpm:"mozilla-js-debuginfo~17.0.7~2.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~17.0.7~2.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-buildsymbols", rpm:"xulrunner-buildsymbols~17.0.7~2.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~17.0.7~2.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debugsource", rpm:"xulrunner-debugsource~17.0.7~2.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~17.0.7~2.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel-debuginfo", rpm:"xulrunner-devel-debuginfo~17.0.7~2.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js-32bit", rpm:"mozilla-js-32bit~17.0.7~2.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-js-debuginfo-32bit", rpm:"mozilla-js-debuginfo-32bit~17.0.7~2.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-32bit", rpm:"xulrunner-32bit~17.0.7~2.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo-32bit", rpm:"xulrunner-debuginfo-32bit~17.0.7~2.46.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
