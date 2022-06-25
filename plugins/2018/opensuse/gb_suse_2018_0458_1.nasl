###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0458_1.nasl 13209 2019-01-22 08:11:01Z mmartin $
#
# SuSE Update for openssl-steam openSUSE-SU-2018:0458-1 (openssl-steam)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851703");
  script_version("$Revision: 13209 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 09:11:01 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-02-17 08:34:15 +0100 (Sat, 17 Feb 2018)");
  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180",
                "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-6302",
                "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-6306", "CVE-2016-7052",
                "CVE-2016-7055", "CVE-2016-7056", "CVE-2017-3731", "CVE-2017-3732");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for openssl-steam openSUSE-SU-2018:0458-1 (openssl-steam)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-steam'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for openssl-steam fixes the following issues:

  - Merged changes from upstream openssl (Factory rev 137) into this fork
  for Steam.

  Updated to openssl 1.0.2k:

  * CVE-2016-7055: Montgomery multiplication may produce incorrect results
  (boo#1009528)

  * CVE-2016-7056: ECSDA P-256 timing attack key recovery (boo#1019334)

  * CVE-2017-3731: Truncated packet could crash via OOB read (boo#1022085)

  * CVE-2017-3732: BN_mod_exp may produce incorrect results on x86_64
  (boo#1022086)

  Update to openssl-1.0.2j:

  * CVE-2016-7052: Missing CRL sanity check (boo#1001148)

  OpenSSL Security Advisory [22 Sep 2016] (boo#999665)

  - Severity: High

  * CVE-2016-6304: OCSP Status Request extension unbounded memory growth
  (boo#999666)

  - Severity: Low

  * CVE-2016-2177: Pointer arithmetic undefined behaviour (boo#982575)

  * CVE-2016-2178: Constant time flag not preserved in DSA signing
  (boo#983249)

  * CVE-2016-2179: DTLS buffered message DoS (boo#994844)

  * CVE-2016-2180: OOB read in TS_OBJ_print_bio() (boo#990419)

  * CVE-2016-2181: DTLS replay protection DoS (boo#994749)

  * CVE-2016-2182: OOB write in BN_bn2dec() (boo#993819)

  * CVE-2016-2183: Birthday attack against 64-bit block ciphers
  (SWEET32) (boo#995359)

  * CVE-2016-6302: Malformed SHA512 ticket DoS (boo#995324)

  * CVE-2016-6303: OOB write in MDC2_Update() (boo#995377)

  * CVE-2016-6306: Certificate message OOB reads (boo#999668)

  ALso fixed:

  - fixed a crash in print_notice (boo#998190)

  - fix X509_CERT_FILE path (boo#1022271) and rename

  - resume reading from /dev/urandom when interrupted by a signal
  (boo#995075)

  - fix problems with locking in FIPS mode (boo#992120)

  * duplicates: boo#991877, boo#991193, boo#990392, boo#990428 and
  boo#990207

  - drop openssl-fips_RSA_compute_d_with_lcm.patch (upstream) (boo#984323)

  - don't check for /etc/system-fips (boo#982268)");
  script_tag(name:"affected", value:"openssl-steam on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-02/msg00032.html");
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

  if ((res = isrpmvuln(pkg:"libopenssl1_0_0-steam", rpm:"libopenssl1_0_0-steam~1.0.2k~4.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl1_0_0-steam-debuginfo", rpm:"libopenssl1_0_0-steam-debuginfo~1.0.2k~4.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-steam-debugsource", rpm:"openssl-steam-debugsource~1.0.2k~4.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl1_0_0-steam-32bit", rpm:"libopenssl1_0_0-steam-32bit~1.0.2k~4.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl1_0_0-steam-debuginfo-32bit", rpm:"libopenssl1_0_0-steam-debuginfo-32bit~1.0.2k~4.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
