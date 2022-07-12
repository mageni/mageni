###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2537_1.nasl 14110 2019-03-12 09:28:23Z cfischer $
#
# SuSE Update for compat-openssl098 openSUSE-SU-2016:2537-1 (compat-openssl098)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851412");
  script_version("$Revision: 14110 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 10:28:23 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-10-15 05:53:17 +0200 (Sat, 15 Oct 2016)");
  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2181",
                "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-6302", "CVE-2016-6303",
                "CVE-2016-6304", "CVE-2016-6306");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for compat-openssl098 openSUSE-SU-2016:2537-1 (compat-openssl098)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'compat-openssl098'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for compat-openssl098 fixes the following issues:

  OpenSSL Security Advisory [22 Sep 2016] (bsc#999665)

  Severity: High

  * OCSP Status Request extension unbounded memory growth (CVE-2016-6304)
  (bsc#999666)

  Severity: Low

  * Pointer arithmetic undefined behaviour (CVE-2016-2177) (bsc#982575)

  * Constant time flag not preserved in DSA signing (CVE-2016-2178)
  (bsc#983249)

  * DTLS buffered message DoS (CVE-2016-2179) (bsc#994844)

  * DTLS replay protection DoS (CVE-2016-2181) (bsc#994749)

  * OOB write in BN_bn2dec() (CVE-2016-2182) (bsc#993819)

  * Birthday attack against 64-bit block ciphers (SWEET32) (CVE-2016-2183)
  (bsc#995359)

  * Malformed SHA512 ticket DoS (CVE-2016-6302) (bsc#995324)

  * OOB write in MDC2_Update() (CVE-2016-6303) (bsc#995377)

  * Certificate message OOB reads (CVE-2016-6306) (bsc#999668)

  More information can be found on the linked vendor advisory.

  Bugs fixed:

  * update expired S/MIME certs (bsc#979475)

  * fix crash in print_notice (bsc#998190)

  * resume reading from /dev/urandom when interrupted by a signal
  (bsc#995075)

  This update was imported from the SUSE:SLE-12:Update update project.");
  script_tag(name:"affected", value:"compat-openssl098 on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20160922.txt");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"compat-openssl098-debugsource", rpm:"compat-openssl098-debugsource~0.9.8j~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8j~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo", rpm:"libopenssl0_9_8-debuginfo~0.9.8j~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8j~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo-32bit", rpm:"libopenssl0_9_8-debuginfo-32bit~0.9.8j~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
