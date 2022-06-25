###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2597_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for libressl openSUSE-SU-2018:2597-1 (libressl)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851876");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-04 07:03:19 +0200 (Tue, 04 Sep 2018)");
  script_cve_id("CVE-2018-12434", "CVE-2018-8970");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for libressl openSUSE-SU-2018:2597-1 (libressl)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libressl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"This update for libressl to version 2.8.0 fixes the following issues:

  Security issues fixed:

  - CVE-2018-12434: Avoid a timing side-channel leak when generating DSA and
  ECDSA signatures. (boo#1097779)

  - Reject excessively large primes in DH key generation.

  - CVE-2018-8970: Fixed a bug in int_x509_param_set_hosts, calling strlen()
  if name length provided is 0 to match the OpenSSL behaviour.
  (boo#1086778)

  - Fixed an out-of-bounds read and crash in DES-fcrypt (boo#1065363)

  You can find a detailed list of changes in the linked references.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-953=1");
  script_tag(name:"affected", value:"libressl on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-09/msg00004.html");
  script_xref(name:"URL", value:"https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.8.0-relnotes");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"libcrypto43", rpm:"libcrypto43~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcrypto43-debuginfo", rpm:"libcrypto43-debuginfo~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libressl", rpm:"libressl~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libressl-debuginfo", rpm:"libressl-debuginfo~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libressl-debugsource", rpm:"libressl-debugsource~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libressl-devel", rpm:"libressl-devel~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libssl45", rpm:"libssl45~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libssl45-debuginfo", rpm:"libssl45-debuginfo~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtls17", rpm:"libtls17~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtls17-debuginfo", rpm:"libtls17-debuginfo~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcrypto43-32bit", rpm:"libcrypto43-32bit~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcrypto43-debuginfo-32bit", rpm:"libcrypto43-debuginfo-32bit~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libressl-devel-32bit", rpm:"libressl-devel-32bit~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libssl45-32bit", rpm:"libssl45-32bit~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libssl45-debuginfo-32bit", rpm:"libssl45-debuginfo-32bit~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtls17-32bit", rpm:"libtls17-32bit~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtls17-debuginfo-32bit", rpm:"libtls17-debuginfo-32bit~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libressl-devel-doc", rpm:"libressl-devel-doc~2.8.0~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
