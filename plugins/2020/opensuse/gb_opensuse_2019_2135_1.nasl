# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852889");
  script_version("2020-01-16T07:19:44+0000");
  script_cve_id("CVE-2018-20174", "CVE-2018-20175", "CVE-2018-20176", "CVE-2018-20177",
                "CVE-2018-20178", "CVE-2018-20179", "CVE-2018-20180", "CVE-2018-20181",
                "CVE-2018-20182", "CVE-2018-8791", "CVE-2018-8792", "CVE-2018-8793",
                "CVE-2018-8794", "CVE-2018-8795", "CVE-2018-8796", "CVE-2018-8797",
                "CVE-2018-8798", "CVE-2018-8799", "CVE-2018-8800");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-16 07:19:44 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:41:30 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE Update for rdesktop openSUSE-SU-2019:2135-1 (rdesktop)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00040.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rdesktop'
  package(s) announced via the openSUSE-SU-2019:2135_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rdesktop fixes the following issues:

  rdesktop was updated to 1.8.6:

  * Fix protocol code handling new licenses

  rdesktop was updated to 1.8.5:

  * Add bounds checking to protocol handling in order to fix many security
  problems when communicating with a malicious server.

  rdesktop was updated to 1.8.4 (fix for boo#1121448):

  * Add rdp_protocol_error function that is used in several fixes

  * Refactor of process_bitmap_updates

  * Fix possible integer overflow in s_check_rem() on 32bit arch

  * Fix memory corruption in process_bitmap_data - CVE-2018-8794

  * Fix remote code execution in process_bitmap_data - CVE-2018-8795

  * Fix remote code execution in process_plane - CVE-2018-8797

  * Fix Denial of Service in mcs_recv_connect_response - CVE-2018-20175

  * Fix Denial of Service in mcs_parse_domain_params - CVE-2018-20175

  * Fix Denial of Service in sec_parse_crypt_info - CVE-2018-20176

  * Fix Denial of Service in sec_recv - CVE-2018-20176

  * Fix minor information leak in rdpdr_process - CVE-2018-8791

  * Fix Denial of Service in cssp_read_tsrequest - CVE-2018-8792

  * Fix remote code execution in cssp_read_tsrequest - CVE-2018-8793

  * Fix Denial of Service in process_bitmap_data - CVE-2018-8796

  * Fix minor information leak in rdpsnd_process_ping - CVE-2018-8798

  * Fix Denial of Service in process_secondary_order - CVE-2018-8799

  * Fix remote code execution in in ui_clip_handle_data - CVE-2018-8800

  * Fix major information leak in ui_clip_handle_data - CVE-2018-20174

  * Fix memory corruption in rdp_in_unistr - CVE-2018-20177

  * Fix Denial of Service in process_demand_active - CVE-2018-20178

  * Fix remote code execution in lspci_process - CVE-2018-20179

  * Fix remote code execution in rdpsnddbg_process - CVE-2018-20180

  * Fix remote code execution in seamless_process - CVE-2018-20181

  * Fix remote code execution in seamless_process_line - CVE-2018-20182

  * Fix building against OpenSSL 1.1

  - remove obsolete patches

  * rdesktop-Fix-OpenSSL-1.1-compability-issues.patch

  * rdesktop-Fix-crash-in-rdssl_cert_to_rkey.patch

  - update changes file

  * add missing info about bugzilla 1121448

  - update to 1.8.6

  * Fix protocol code handling new licenses

  - update to 1.8.5

  * Add bounds checking to protocol handling in order to fix many security
  problems when communicating with a malicious server.

  - Trim redundant wording from descrip ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'rdesktop' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"rdesktop", rpm:"rdesktop~1.8.6~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rdesktop-debuginfo", rpm:"rdesktop-debuginfo~1.8.6~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rdesktop-debugsource", rpm:"rdesktop-debugsource~1.8.6~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
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
