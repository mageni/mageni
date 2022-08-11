###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1689_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for bouncycastle openSUSE-SU-2018:1689-1 (bouncycastle)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851785");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-06-15 05:48:03 +0200 (Fri, 15 Jun 2018)");
  script_cve_id("CVE-2016-1000338", "CVE-2016-1000339", "CVE-2016-1000340", "CVE-2016-1000341",
                "CVE-2016-1000342", "CVE-2016-1000343", "CVE-2016-1000344", "CVE-2016-1000345",
                "CVE-2016-1000346", "CVE-2016-1000352", "CVE-2017-13098");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for bouncycastle openSUSE-SU-2018:1689-1 (bouncycastle)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'bouncycastle'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"This update for bouncycastle to version 1.59 fixes the following issues:

  These security issues were fixed:

  - CVE-2017-13098: BouncyCastle, when configured to use the JCE (Java
  Cryptography Extension) for cryptographic functions, provided a weak
  Bleichenbacher oracle when any TLS cipher suite using RSA key exchange
  was negotiated. An attacker can recover the private key from a
  vulnerable application. This vulnerability is referred to as 'ROBOT'
  (bsc#1072697).

  - CVE-2016-1000338: Ensure full validation of ASN.1 encoding of signature
  on verification. It was possible to inject extra elements in the
  sequence making up the signature and still have it validate, which in
  some cases may have allowed the introduction of 'invisible' data into a
  signed structure (bsc#1095722).

  - CVE-2016-1000339: Prevent AESEngine key information leak via lookup
  table accesses (boo#1095853).

  - CVE-2016-1000340: Preventcarry propagation bugs in the implementation of
  squaring for several raw math classes (boo#1095854).

  - CVE-2016-1000341: Fix DSA signature generation vulnerability to timing
  attack (boo#1095852).

  - CVE-2016-1000341: DSA signature generation was vulnerable to timing
  attack. Where timings can be closely observed for the generation of
  signatures may have allowed an attacker to gain information about the
  signature's k value and ultimately the private value as well
  (bsc#1095852).

  - CVE-2016-1000342: Ensure that ECDSA does fully validate ASN.1 encoding
  of signature on verification. It was possible to inject extra elements
  in the sequence making up the signature and still have it validate,
  which in some cases may have allowed the introduction of 'invisible'
  data into a signed structure (bsc#1095850).

  - CVE-2016-1000343: Prevent weak default settings for private DSA key pair
  generation (boo#1095849).

  - CVE-2016-1000344: Removed DHIES from the provider to disable the unsafe
  usage
  of ECB mode (boo#1096026).

  - CVE-2016-1000345: The DHIES/ECIES CBC mode was vulnerable to padding
  oracle attack. In an environment where timings can be easily observed,
  it was possible with enough observations to identify when the decryption
  is failing due to padding (bsc#1096025).

  - CVE-2016-1000346: The other party DH public key was not fully validated.
  This could have caused issues as invalid keys could be used to reveal
  details about the other party's private key where static Diffie-Hellman
  is in use (bsc#1096024).

  - CVE-2016-1000352: Remove ECIES from the provider to disable the unsafe
  usage
  of ECB mode (boo#1096022).


  Patch Instr ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"bouncycastle on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-06/msg00025.html");
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

  if ((res = isrpmvuln(pkg:"bouncycastle", rpm:"bouncycastle~1.59~23.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bouncycastle-javadoc", rpm:"bouncycastle-javadoc~1.59~23.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
