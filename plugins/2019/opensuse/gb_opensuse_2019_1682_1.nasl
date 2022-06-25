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
  script_oid("1.3.6.1.4.1.25623.1.0.852606");
  script_version("2019-07-04T09:58:18+0000");
  script_cve_id("CVE-2018-16860", "CVE-2019-12098");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-07-04 09:58:18 +0000 (Thu, 04 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-02 02:00:56 +0000 (Tue, 02 Jul 2019)");
  script_name("openSUSE Update for libheimdal openSUSE-SU-2019:1682-1 (libheimdal)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.3|openSUSELeap15\.0)");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00002.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libheimdal'
  package(s) announced via the openSUSE-SU-2019:1682_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libheimdal fixes the following issues:

  libheimdal was updated to version 7.7.0:

  + Bug fixes:

  - PKCS#11 hcrypto back-end:

  + initialize the p11_module_load function list
  + verify that not only is a mechanism present but that its mechanism
  info states that it offers the required encryption, decryption or
  digest services

  - krb5:

  + Starting with 7.6, Heimdal permitted requesting authenticated
  anonymous tickets. However, it did not verify that a KDC in fact
  returned an anonymous ticket when one was requested.
  + Cease setting the KDCOption reaquest_anonymous flag when issuing
  S4UProxy (constrained delegation) TGS requests.
  + when the Win2K PKINIT compatibility option is set, do not require
  krbtgt otherName to match when validating KDC certificate.
  + set PKINIT_BTMM flag per Apple implementation
  + use memset_s() instead of memset()

  - kdc:

  + When generating KRB5SignedPath in the AS, use the reply client name
  rather than the one from the request, so validation will work
  correctly in the TGS.
  + allow checksum of PA-FOR-USER to be HMAC_MD5. Even if TGT used an
  enctype with a different checksum. Per [MS-SFU] 2.2.1 PA-FOR-USER
  the checksum is always HMAC_MD5, and that's what Windows and MIT
  clients send. In Heimdal both the client and kdc use instead the
  checksum of the TGT, and therefore work with each other but Windows
  and MIT clients fail against Heimdal KDC. Both Windows and MIT KDC
  would allow any keyed checksum to be used so Heimdal client work
  fine against it. Change Heimdal KDC to allow HMAC_MD5 even for non
  RC4 based TGT in order to support per-spec clients.
  + use memset_s() instead of memset()
  + Detect Heimdal 1.0 through 7.6 clients that issue S4UProxy
  (constrained delegation) TGS Requests with the request anonymous
  flag set. These requests will be treated as S4UProxy requests and
  not anonymous requests.

  - HDB:

  + Set SQLite3 backend default page size to 8KB.
  + Add hdb_set_sync() method

  - kadmind:

  + disable HDB sync during database load avoiding unnecessary disk i/o.

  - ipropd:

  + disable HDB sync during receive_everything. Doing an fsync
  per-record when receiving the complete HDB is a performance
  disaster. Among other things, if the HDB is very large, then one
  slave receiving a full HDB can cause
  other slaves to timeout and, if HDB write activity is high enough to
  cause iprop log truncation, then also need full syncs, which leads to a
  cycle of full syncs for all slaves until HDB write activity drops.
  Allowing the iprop log to be larger helps, b ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'libheimdal' package(s) on openSUSE Leap 42.3, openSUSE Leap 15.0.");

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

if(release == "openSUSELeap42.3") {

  if(!isnull(res = isrpmvuln(pkg:"libheimdal", rpm:"libheimdal~7.7.0~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheimdal-debuginfo", rpm:"libheimdal-debuginfo~7.7.0~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheimdal-debugsource", rpm:"libheimdal-debugsource~7.7.0~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheimdal-devel", rpm:"libheimdal-devel~7.7.0~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libheimdal", rpm:"libheimdal~7.7.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheimdal-debuginfo", rpm:"libheimdal-debuginfo~7.7.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheimdal-debugsource", rpm:"libheimdal-debugsource~7.7.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheimdal-devel", rpm:"libheimdal-devel~7.7.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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
