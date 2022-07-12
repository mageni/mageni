###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_2257_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for mbedtls openSUSE-SU-2015:2257-1 (mbedtls)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851187");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-02-02 17:17:06 +0100 (Tue, 02 Feb 2016)");
  script_cve_id("CVE-2015-5291");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for mbedtls openSUSE-SU-2015:2257-1 (mbedtls)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mbedtls'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for mbedtls fixes the following security and non-security
  issues:

  - Update to 1.3.15

  * Fix potential double free if ssl_set_psk() is called more than once
  and some allocation fails. Cannot be forced remotely. Found by Guido
  Vranken, Intelworks.

  * Fix potential heap corruption on windows when x509_crt_parse_path() is
  passed a path longer than 2GB. Cannot be triggered remotely. Found by
  Guido Vranken, Intelworks.

  * Fix potential buffer overflow in some asn1_write_xxx() functions.
  Cannot be triggered remotely unless you create X.509 certificates based
  on untrusted input or write keys of untrusted origin. Found by Guido
  Vranken, Intelworks.

  * The x509 max_pathlen constraint was not enforced on intermediate
  certificates. Found by Nicholas Wilson, fix and tests provided by
  Janos Follath. #280 and #319

  * Self-signed certificates were not excluded from pathlen counting,
  resulting in some valid X.509 being incorrectly rejected. Found and
  fix provided by Janos Follath. #319

  * Fix bug causing some handshakes to fail due to some non-fatal alerts
  not begin properly ignored. Found by mancha and Kasom Koht-arsa, #308

  * Fix build error with configurations where ecdhe-psk is the only key
  exchange. Found and fix provided by Chris Hammond. #270

  * Fix failures in mpi on sparc(64) due to use of bad assembly code.
  Found by Kurt Danielson. #292

  * Fix typo in name of the extkeyusage oid. found by inestlerode, #314

  * Fix bug in asn.1 encoding of booleans that caused generated ca
  certificates to be rejected by some applications, including OS X
  Keychain. Found and fixed by Jonathan Leroy, Inikup.

  * Fix 'destination buffer is too small' error in cert_write program.
  Found and fixed by Jonathan Leroy, Inikup.

  - Update to 1.3.14

  * Added fix for CVE-2015-5291 (boo#949380) to prevent heap corruption
  due to buffer
  overflow of the hostname or session ticket. Found by Guido Vranken,
  Intelworks.

  * Fix stack buffer overflow in pkcs12 decryption (used by
  mbedtls_pk_parse_key(file)() when the password is   129 bytes. Found
  by Guido Vranken, Intelworks. Not triggerable remotely.

  * Fix potential buffer overflow in mbedtls_mpi_read_string(). Found by
  Guido Vranken, Intelworks. Not exploitable remotely in the context
  of TLS, but might be in other uses. On 32 bit machines, requires
  reading a string of close to or larger than 1GB to exploit  on 64 bit
  machines, would require reading a string of close to or larger than
  2^62 bytes.

  * Fix potential random memory allocation in mbedtls_pem_read_buffer()
  on crafted PEM input data. ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"mbedtls on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"libmbedtls9", rpm:"libmbedtls9~1.3.15~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmbedtls9-debuginfo", rpm:"libmbedtls9-debuginfo~1.3.15~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mbedtls-debugsource", rpm:"mbedtls-debugsource~1.3.15~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mbedtls-devel", rpm:"mbedtls-devel~1.3.15~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmbedtls9-32bit", rpm:"libmbedtls9-32bit~1.3.15~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmbedtls9-debuginfo-32bit", rpm:"libmbedtls9-debuginfo-32bit~1.3.15~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
