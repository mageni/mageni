# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852670");
  script_version("2019-08-20T10:47:01+0000");
  # TODO: No CVE assigned yet.  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-08-20 10:47:01 +0000 (Tue, 20 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-20 02:00:59 +0000 (Tue, 20 Aug 2019)");
  script_name("openSUSE Update for Recommended openSUSE-SU-2019:1951-1 (Recommended)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00061.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Recommended'
  package(s) announced via the openSUSE-SU-2019:1951_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dkgpg, libTMCG fixes the following issues:

  libTMCG was updated to version 1.3.18

  * This release is two-fold: first, it fixes some bugs (e.g. iterated S2K)
  of the OpenPGP interface, and second, it adds functionality for handling
  v5 keys and signatures (see RFC 4880bis-07).

  Update to version 1.3.17

  * VTMF, ASTC, DKG, VRHE, EOTP, COM, VSS: make CheckGroup() more robust

  * VSSHE: security bugfix for Verify_[non]interactive_[_publiccoin]

  * mpz_spowm: added check for correct base in fast exponentiation

  * mpz_sqrtm: remove unused parameter in tmcg_mpz_qrmn_p()

  * configure.ac: added compiler option '-Wextra'

  * mpz_sprime: added tmcg_mpz_smprime() with increased B = 80000

  * RFC4880: changed type of tmcg_openpgp_mem_alloc to unsigned long

  Update to version 1.3.16

  * changed constant TMCG_MAX_CARDS (decreased by factor 2)

  * changed formulas for TMCG_MAX_VALUE_CHARS and TMCG_MAX_KEY_CHARS

  * RFC4880: added support of Preferred AEAD Algorithms [RFC 4880bis]

  * RFC4880: added output for key usage 'timestamping' [RFC 4880bis]

  * RFC4880: changed tmcg_openpgp_byte_t: unsigned char -> uint8_t

  * RFC4880: added PacketAeadEncode() [RFC 4880bis]

  * RFC4880: added SymmetricDecryptAEAD() and SymmetricEncryptAEAD()

  * changed formula for TMCG_MAX_KEYBITS (increased by factor 2)

  * mpz_srandom: bugfix in Botan code branch of mpz_grandomb()

  Update to version 1.3.15:

  * This is a maintenance release that fixes some bugs, e.g. in the Botan
  support of functions from module mpz_srandom. Moreover, some interfaces
  of the OpenPGP implementation have been added and removed. For some
  modules of LibTMCG a basic exception handling has been introduced.

  Update to version 1.3.14:

  * With this release three additional parameters for the control of secure
  memory allocation have been added to init_libTMCG(). They are explained
  in the reference manual. Moreover, the OpenPGP interface has been
  enhanced in several way, e.g., ECDH, ECDSA and EdDSA are supported now.

  Update to 1.3.13:

  * Lots of major improvements for undocumented OpenPGP interface

  * PRNG from Botan is used as additional source of randomness

  * SHA3 is emulated if runtime version of libgcrypt is too old

  dkgpg was updated to version 1.1.3:

  * This is a bugfix release that includes only three minor improvements: a
  direct-key signature (0x1f) for the primary key is added by default such
  that restricting key servers (e.g. keys.openpgp.org) can deliver a
  cryptographically checkable key without verification of any included
  user ID or without appended subkey. The command line i ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'Recommended' package(s) on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"dkgpg", rpm:"dkgpg~1.1.3~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkgpg-debuginfo", rpm:"dkgpg-debuginfo~1.1.3~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkgpg-debugsource", rpm:"dkgpg-debugsource~1.1.3~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libTMCG-debugsource", rpm:"libTMCG-debugsource~1.3.18~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libTMCG-devel", rpm:"libTMCG-devel~1.3.18~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libTMCG18", rpm:"libTMCG18~1.3.18~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libTMCG18-debuginfo", rpm:"libTMCG18-debuginfo~1.3.18~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
