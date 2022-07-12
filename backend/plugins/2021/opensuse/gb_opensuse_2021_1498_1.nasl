# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.854310");
  script_version("2021-11-29T04:48:32+0000");
  script_cve_id("CVE-2021-42072", "CVE-2021-42073");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-29 10:38:15 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-23 02:02:05 +0000 (Tue, 23 Nov 2021)");
  script_name("openSUSE: Security Advisory for barrier (openSUSE-SU-2021:1498-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1498-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/74GXCIF4KQYNWDBG745K5PJQT5VK2BHK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'barrier'
  package(s) announced via the openSUSE-SU-2021:1498-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for barrier fixes the following issues:

     Updated to version 2.4.0:

     Barrier now supports client identity verification (fixes CVE-2021-42072,
     CVE-2021-42073).

     Previously a malicious client could connect to Barrier server without any
     authentication and send application-level messages. This made the attack
     surface of Barrier significantly larger. Additionally, in case the
     malicious client got possession of a valid screen name by brute forcing or
     other means it could modify the clipboard contents of the server. To
     support seamless upgrades from older versions of Barrier this is currently
     disabled by default. The feature can be enabled in the settings dialog. If
     enabled, older clients of Barrier will be rejected. Barrier now uses
     SHA256 fingerprints for establishing security of encrypted SSL
     connections. After upgrading client to new version the existing server
     fingerprint will need to be approved again. Client and server will show
     both SHA1 and SHA256 server fingerprints to allow interoperability with
     older versions of Barrier.

     Bugfixes:

  * Fixed build failure on mips*el and riscv64 architecture.

  * Barrier no longer uses openssl CLI tool for any operations and hooks
       into the openssl library directly.

  * More X11 clipboard MIME types have been mapped to corresponding
       converters (#344).

  * Fixed setup of multiple actions associated with a hotkey.

  * Fixed setup of hotkeys with special characters such as comma and
       semicolon (#778).

  * Fixed transfer of non-ASCII characters coming from a Windows server in
       certain cases (#527).

  * Barrier will now regenerate server certificate if it&#x27 s invalid instead
       of failing to launch (#802)

  * Added support for additional keys on Sun Microsystems USB keyboards
       (#784).

  * Updated Chinese translation.

  * Updated Slovak translation.

  * Theme icons are now preferred to icons distributed together with Barrier
       (#471).

     Features:

  * Added --drop-target option that improves drag and drop support on
       Windows when Barrier is being run as a portable app.

  * The --enable-crypto command line option has been made the default to
       reduce chances of accidental security mishaps when configuring Barrier
       from command line. A new --disable-crypto command line option has been
       added to explicitly disable encryption.

  * Added support for randomart images for easier comparison of SSL
       certificate fingerprints. The algorithm is identica ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'barrier' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"barrier", rpm:"barrier~2.4.0~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"barrier-debuginfo", rpm:"barrier-debuginfo~2.4.0~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"barrier-debugsource", rpm:"barrier-debugsource~2.4.0~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);