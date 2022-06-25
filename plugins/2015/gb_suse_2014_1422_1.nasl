###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1422_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for java-1_7_0-openjdk SUSE-SU-2014:1422-1 (java-1_7_0-openjdk)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850955");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 14:59:52 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2014-6457", "CVE-2014-6502", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6513", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6531", "CVE-2014-6558");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for java-1_7_0-openjdk SUSE-SU-2014:1422-1 (java-1_7_0-openjdk)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenJDK was updated to icedtea 2.5.3 (OpenJDK 7u71) fixing security issues
  and bugs.

  * Security:

  - S8015256: Better class accessibility

  - S8022783, CVE-2014-6504: Optimize C2 optimizations

  - S8035162: Service printing service

  - S8035781: Improve equality for annotations

  - S8036805: Correct linker method lookup.

  - S8036810: Correct linker field lookup

  - S8036936: Use local locales

  - S8037066, CVE-2014-6457: Secure transport layer

  - S8037846, CVE-2014-6558: Ensure streaming of input cipher streams

  - S8038364: Use certificate exceptions correctly

  - S8038899: Safer safepoints

  - S8038903: More native monitor monitoring

  - S8038908: Make Signature more robust

  - S8038913: Bolster XML support

  - S8039509, CVE-2014-6512: Wrap sockets more thoroughly

  - S8039533, CVE-2014-6517: Higher resolution resolvers

  - S8041540, CVE-2014-6511: Better use of pages in font processing

  - S8041529: Better parameterization of parameter lists

  - S8041545: Better validation of generated rasters

  - S8041564, CVE-2014-6506: Improved management of logger resources

  - S8041717, CVE-2014-6519: Issue with class file parser

  - S8042609, CVE-2014-6513: Limit splashiness of splash images

  - S8042797, CVE-2014-6502: Avoid strawberries in LogRecord

  - S8044274, CVE-2014-6531: Proper property processing

  * Backports:

  - S4963723: Implement SHA-224

  - S7044060: Need to support NSA Suite B Cryptography algorithms

  - S7122142: (ann) Race condition between isAnnotationPresent and
  getAnnotations

  - S7160837: DigestOutputStream does not turn off digest calculation when
  'close()' is called

  - S8006935: Need to take care of long secret keys in HMAC/PRF computation

  - S8012637: Adjust CipherInputStream class to work in AEAD/GCM mode

  - S8028192: Use of PKCS11-NSS provider in FIPS mode broken

  - S8038000: java.awt.image.RasterFormatException: Incorrect scanline stride

  - S8039396: NPE when writing a class descriptor object to a custom
  ObjectOutputStream

  - S8042603:'SafepointPollOffset' was not declared in static member
  function 'static bool Arguments::check_vm_args_consistency()'

  - S8042850: Extra unused entries in ICU ScriptCodes enum

  - S8052162: REGRESSION: sun/java2d/cmm/ColorConvertOp tests fail since
  7u71 b01

  - S8053963: (dc) Use DatagramChannel.receive() instead of read() in
  connect()

  - S8055176: 7u71 l10n resource file translation update

  * Bugfixes:

  - PR1988: C++ Interpreter should no longer be used on ppc64

  - PR1989: Make jdk_generic_profile.sh handle missing programs better and
  be mo ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"java-1_7_0-openjdk on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(SLED12\.0SP0|SLES12\.0SP0)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED12.0SP0")
{

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.71~6.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.71~6.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.71~6.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.71~6.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless-debuginfo", rpm:"java-1_7_0-openjdk-headless-debuginfo~1.7.0.71~6.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "SLES12.0SP0")
{

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.71~6.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.71~6.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.71~6.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.71~6.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo-debuginfo", rpm:"java-1_7_0-openjdk-demo-debuginfo~1.7.0.71~6.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.71~6.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel-debuginfo", rpm:"java-1_7_0-openjdk-devel-debuginfo~1.7.0.71~6.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.71~6.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless-debuginfo", rpm:"java-1_7_0-openjdk-headless-debuginfo~1.7.0.71~6.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
