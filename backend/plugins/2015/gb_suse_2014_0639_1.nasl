###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0639_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for OpenJDK SUSE-SU-2014:0639-1 (OpenJDK)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851107");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 20:10:12 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2013-6629", "CVE-2013-6954", "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0454", "CVE-2014-0455", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-1876", "CVE-2014-2397", "CVE-2014-2398", "CVE-2014-2402", "CVE-2014-2403", "CVE-2014-2412", "CVE-2014-2413", "CVE-2014-2414", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for OpenJDK SUSE-SU-2014:0639-1 (OpenJDK)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenJDK'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This java-1_7_0-openjdk update to version 2.4.7 fixes the following
  security and non-security issues:

  *

  Security fixes

  o S8023046: Enhance splashscreen support o S8025005: Enhance
  CORBA initializations o S8025010, CVE-2014-2412: Enhance AWT contexts o
  S8025030, CVE-2014-2414: Enhance stream handling o S8025152,
  CVE-2014-0458: Enhance activation set up o S8026067: Enhance signed jar
  verification o S8026163, CVE-2014-2427: Enhance media provisioning o
  S8026188, CVE-2014-2423: Enhance envelope factory o S8026200: Enhance
  RowSet Factory o S8026716, CVE-2014-2402: (aio) Enhance asynchronous
  channel handling o S8026736, CVE-2014-2398: Enhance Javadoc pages o
  S8026797, CVE-2014-0451: Enhance data transfers o S8026801, CVE-2014-0452:
  Enhance endpoint addressing o S8027766, CVE-2014-0453: Enhance RSA
  processing o S8027775: Enhance ICU code. o S8027841, CVE-2014-0429:
  Enhance pixel manipulations o S8028385: Enhance RowSet Factory o S8029282,
  CVE-2014-2403: Enhance CharInfo set up o S8029286: Enhance subject
  delegation o S8029699: Update Poller demo o S8029730: Improve audio device
  additions o S8029735: Enhance service mgmt natives o S8029740,
  CVE-2014-0446: Enhance handling of loggers o S8029745, CVE-2014-0454:
  Enhance algorithm checking o S8029750: Enhance LCMS color processing
  (in-tree LCMS) o S8029760, CVE-2013-6629: Enhance AWT image libraries
  (in-tree libjpeg) o S8029844, CVE-2014-0455: Enhance argument validation o
  S8029854, CVE-2014-2421: Enhance JPEG decodings o S8029858, CVE-2014-0456:
  Enhance array copies o S8030731, CVE-2014-0460: Improve name service
  robustness o S8031330: Refactor ObjectFactory o S8031335, CVE-2014-0459:
  Better color profiling (in-tree LCMS) o S8031352, CVE-2013-6954: Enhance
  PNG handling (in-tree libpng) o S8031394, CVE-2014-0457: (sl) Fix
  exception handling in ServiceLoader o S8031395: Enhance LDAP processing o
  S8032686, CVE-2014-2413: Issues with method invoke o S8033618,
  CVE-2014-1876: Correct logging output o S8034926, CVE-2014-2397: Attribute
  classes properly o S8036794, CVE-2014-0461: Manage JavaScript instances
  *

  Backports

  o S8004145: New improved hgforest.sh, ctrl-c now properly
  terminates mercurial processes. o S8007625: race with nested repos in
  /common/bin/hgforest.sh o S8011178: improve common/bin/hgforest.sh python
  detection (MacOS) o S8011342: hgforest.sh:'python --version' not
  supported on older python o S8011350: hgforest.sh uses non-POSIX sh
  features that may fail with some shells o S8024200: handle hg wrapper with
  space after #! o S8025796: h ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"OpenJDK on SUSE Linux Enterprise Desktop 11 SP3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED11.0SP3")
{

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.6~0.27.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.6~0.27.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.6~0.27.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}