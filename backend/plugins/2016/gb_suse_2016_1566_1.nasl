###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1566_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for nodejs openSUSE-SU-2016:1566-1 (nodejs)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851337");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-15 05:21:39 +0200 (Wed, 15 Jun 2016)");
  script_cve_id("CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-2105",
                "CVE-2016-2107");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for nodejs openSUSE-SU-2016:1566-1 (nodejs)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for nodejs to version 4.4.5 fixes the several issues.

  These security issues introduced by the bundled openssl were fixed by
  going to version 1.0.2h:

  - CVE-2016-2107: The AES-NI implementation in OpenSSL did not consider
  memory allocation during a certain padding check, which allowed remote
  attackers to obtain sensitive cleartext information via a padding-oracle
  attack against an AES CBC session (bsc#977616).

  - CVE-2016-2105: Integer overflow in the EVP_EncodeUpdate function in
  crypto/evp/encode.c in OpenSSL allowed remote attackers to cause a
  denial of service (heap memory corruption) via a large amount of binary
  data (bsc#977614).

  - CVE-2016-0705: Double free vulnerability in the dsa_priv_decode function
  in crypto/dsa/dsa_ameth.c in OpenSSL allowed remote attackers to cause a
  denial of service (memory corruption) or possibly have unspecified other
  impact via a malformed DSA private key (bsc#968047).

  - CVE-2016-0797: Multiple integer overflows in OpenSSL allowed remote
  attackers to cause a denial of service (heap memory corruption or NULL
  pointer dereference) or possibly have unspecified other impact via a
  long digit string that is mishandled by the (1) BN_dec2bn or (2)
  BN_hex2bn function, related to crypto/bn/bn.h and crypto/bn/bn_print.c
  (bsc#968048).

  - CVE-2016-0702: The MOD_EXP_CTIME_COPY_FROM_PREBUF function in
  crypto/bn/bn_exp.c in OpenSSL did not properly consider cache-bank
  access times during modular exponentiation, which made it easier for
  local users to discover RSA keys by running a crafted application on the
  same Intel Sandy Bridge CPU core as a victim and leveraging cache-bank
  conflicts, aka a 'CacheBleed' attack (bsc#968050).

  These non-security issues were fixed:

  - Fix faulty 'if' condition (string cannot equal a boolean).

  - buffer: Buffer no longer errors if you call lastIndexOf with a search
  term longer than the buffer.

  - contextify: Context objects are now properly garbage collected, this
  solves a problem some individuals were experiencing with extreme memory
  growth.

  - Update npm to 2.15.5.

  - http: Invalid status codes can no longer be sent. Limited to 3 digit
  numbers between 100 - 999.

  - deps: Fix --gdbjit for embedders. Backported from v8 upstream.

  - querystring: Restore throw when attempting to stringify bad surrogate
  pair.

  - https: Under certain conditions SSL sockets may have been causing a
  memory leak when keepalive is enabled. This is no longer the case.

  - lib: The way that we were internally passing arguments was causing a
  potential leak. By copy ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"nodejs on openSUSE Leap 42.1, openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~4.4.5~18.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs-debuginfo", rpm:"nodejs-debuginfo~4.4.5~18.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs-debugsource", rpm:"nodejs-debugsource~4.4.5~18.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~4.4.5~18.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs-doc", rpm:"nodejs-doc~4.4.5~18.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
