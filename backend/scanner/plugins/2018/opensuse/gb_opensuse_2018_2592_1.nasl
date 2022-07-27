###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2592_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for libressl openSUSE-SU-2018:2592-1 (libressl)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852047");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-12434");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:37:51 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for libressl openSUSE-SU-2018:2592-1 (libressl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-09/msg00003.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libressl'
  package(s) announced via the openSUSE-SU-2018:2592_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libressl to version 2.8.0 fixes the following issues:

  Security issues fixed:

  - CVE-2018-12434: Avoid a timing side-channel leak when generating DSA and
  ECDSA signatures. (boo#1097779)

  - Reject excessively large primes in DH key generation.

  Other bugs fixed:

  - Fixed a pair of 20+ year-old bugs in X509_NAME_add_entry.

  - Tighten up checks for various X509_VERIFY_PARAM functions, 'poisoning'
  parameters so that an unverified certificate cannot be used if it fails
  verification.

  - Fixed a potential memory leak on failure in ASN1_item_digest.

  - Fixed a potential memory alignment crash in asn1_item_combine_free.

  - Removed unused SSL3_FLAGS_DELAY_CLIENT_FINISHED and
  SSL3_FLAGS_POP_BUFFER flags in write path, simplifying IO paths.

  - Removed SSL_OP_TLS_ROLLBACK_BUG buggy client workarounds.

  - Added const annotations to many existing APIs from OpenSSL, making
  interoperability easier for downstream applications.

  - Added a missing bounds check in c2i_ASN1_BIT_STRING.

  - Removed three remaining single DES cipher suites.

  - Fixed a potential leak/incorrect return value in DSA signature
  generation.

  - Added a blinding value when generating DSA and ECDSA signatures, in
  order to reduce the possibility of a side-channel attack leaking the
  private key.

  - Added ECC constant time scalar multiplication support.

  - Revised the implementation of RSASSA-PKCS1-v1_5 to match the
  specification in RFC 8017.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-950=1");

  script_tag(name:"affected", value:"libressl on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"libcrypto43", rpm:"libcrypto43~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcrypto43-debuginfo", rpm:"libcrypto43-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libressl", rpm:"libressl~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libressl-debuginfo", rpm:"libressl-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libressl-debugsource", rpm:"libressl-debugsource~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libressl-devel", rpm:"libressl-devel~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libssl45", rpm:"libssl45~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libssl45-debuginfo", rpm:"libssl45-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtls17", rpm:"libtls17~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtls17-debuginfo", rpm:"libtls17-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libressl-devel-doc", rpm:"libressl-devel-doc~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcrypto43-32bit", rpm:"libcrypto43-32bit~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcrypto43-32bit-debuginfo", rpm:"libcrypto43-32bit-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libressl-devel-32bit", rpm:"libressl-devel-32bit~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libssl45-32bit", rpm:"libssl45-32bit~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libssl45-32bit-debuginfo", rpm:"libssl45-32bit-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtls17-32bit", rpm:"libtls17-32bit~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtls17-32bit-debuginfo", rpm:"libtls17-32bit-debuginfo~2.8.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
