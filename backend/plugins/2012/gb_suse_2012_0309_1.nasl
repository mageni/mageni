###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_0309_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for java-1_6_0-openjdk openSUSE-SU-2012:0309-1 (java-1_6_0-openjdk)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850255");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-08-02 23:00:08 +0530 (Thu, 02 Aug 2012)");
  script_cve_id("CVE-2011-3563", "CVE-2011-3571", "CVE-2011-5035", "CVE-2012-0497",
                "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505",
                "CVE-2012-0506");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for java-1_6_0-openjdk openSUSE-SU-2012:0309-1 (java-1_6_0-openjdk)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_6_0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE11\.4");
  script_tag(name:"affected", value:"java-1_6_0-openjdk on openSUSE 11.4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"java-1_6_0-openjdk was updated to the b24 release, fixing
  multiple security issues:

  * Security fixes

  - S7082299, CVE-2011-3571: Fix inAtomicReferenceArray

  - S7088367, CVE-2011-3563: Fix issues in java sound

  - S7110683, CVE-2012-0502: Issues with some
  KeyboardFocusManager method

  - S7110687, CVE-2012-0503: Issues with TimeZone class

  - S7110700, CVE-2012-0505: Enhance exception throwing
  mechanism in ObjectStreamClass

  - S7110704, CVE-2012-0506: Issues with some method in corba

  - S7112642, CVE-2012-0497: Incorrect checking for graphics
  rendering object

  - S7118283, CVE-2012-0501: Better input parameter checking
  in zip file processing

  - S7126960, CVE-2011-5035: (httpserver) Add property to
  limit number of request headers to the  HTTP Server");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk", rpm:"java-1_6_0-openjdk~1.6.0.0_b24.1.11.1~0.3.2", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk-devel", rpm:"java-1_6_0-openjdk-devel~1.6.0.0_b24.1.11.1~0.3.2", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk-demo", rpm:"java-1_6_0-openjdk-demo~1.6.0.0_b24.1.11.1~0.3.2", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk-javadoc", rpm:"java-1_6_0-openjdk-javadoc~1.6.0.0_b24.1.11.1~0.3.2", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-openjdk-src", rpm:"java-1_6_0-openjdk-src~1.6.0.0_b24.1.11.1~0.3.2", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
