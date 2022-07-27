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
  script_oid("1.3.6.1.4.1.25623.1.0.853038");
  script_version("2020-02-20T11:12:08+0000");
  script_cve_id("CVE-2017-13082", "CVE-2019-9494", "CVE-2019-9495", "CVE-2019-9496", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-02-20 11:12:08 +0000 (Thu, 20 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-16 04:00:26 +0000 (Sun, 16 Feb 2020)");
  script_name("openSUSE: Security Advisory for hostapd (openSUSE-SU-2020:0222-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00021.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hostapd'
  package(s) announced via the openSUSE-SU-2020:0222-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hostapd fixes the following issues:

  hostapd was updated to version 2.9:

  * SAE changes

  - disable use of groups using Brainpool curves

  - improved protection against side channel attacks

  * EAP-pwd changes

  - disable use of groups using Brainpool curves

  - improved protection against side channel attacks

  * fixed FT-EAP initial mobility domain association using PMKSA caching

  * added configuration of airtime policy

  * fixed FILS to and RSNE into (Re)Association Response frames

  * fixed DPP bootstrapping URI parser of channel list

  * added support for regulatory WMM limitation (for ETSI)

  * added support for MACsec Key Agreement using IEEE 802.1X/PSK

  * added experimental support for EAP-TEAP server (RFC 7170)

  * added experimental support for EAP-TLS server with TLS v1.3

  * added support for two server certificates/keys (RSA/ECC)

  * added AKMSuiteSelector into 'STA <addr>' control interface data to
  determine with AKM was used for an association

  * added eap_sim_id parameter to allow EAP-SIM/AKA server pseudonym and
  fast reauthentication use to be disabled

  * fixed an ECDH operation corner case with OpenSSL

  Update to version 2.8

  * SAE changes

  - added support for SAE Password Identifier

  - changed default configuration to enable only group 19 (i.e., disable
  groups 20, 21, 25, 26 from default configuration) and disable all
  unsuitable groups completely based on REVmd changes

  - improved anti-clogging token mechanism and SAE authentication frame
  processing during heavy CPU load, this mitigates some issues with
  potential DoS attacks trying to flood an AP with large number
  of SAE messages

  - added Finite Cyclic Group field in status code 77 responses

  - reject use of unsuitable groups based on new implementation guidance
  in REVmd (allow only FFC groups with prime >= 3072 bits and ECC groups
  with prime >= 256)

  - verify peer scalar ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'hostapd' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"hostapd", rpm:"hostapd~2.9~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hostapd-debuginfo", rpm:"hostapd-debuginfo~2.9~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hostapd-debugsource", rpm:"hostapd-debugsource~2.9~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
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
