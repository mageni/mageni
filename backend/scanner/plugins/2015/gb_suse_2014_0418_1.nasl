###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for MozillaFirefox SUSE-SU-2014:0418-1 (MozillaFirefox)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850803");
  script_version("2019-05-24T11:20:30+0000");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1496", "CVE-2014-1497",
                "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1501",
                "CVE-2014-1502", "CVE-2014-1504", "CVE-2014-1508", "CVE-2014-1509",
                "CVE-2014-1505", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512",
                "CVE-2014-1513", "CVE-2014-1514");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaFirefox SUSE-SU-2014:0418-1 (MozillaFirefox)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox was updated to 24.4.0ESR release, fixing
  various security  issues and bugs:

  *

  MFSA 2014-15: Mozilla developers and community
  identified identified and fixed several memory safety bugs
  in the browser engine used in Firefox and other
  Mozilla-based products. Some of these bugs showed evidence
  of memory corruption under certain circumstances, and we
  presume that with enough effort at least some of these
  could be exploited to run arbitrary code.

  *

  Benoit Jacob, Olli Pettay, Jan Varga, Jan de Mooij,
  Jesse Ruderman, Dan Gohman, and Christoph Diehl reported
  memory safety problems and crashes that affect Firefox ESR
  24.3 and Firefox 27. (CVE-2014-1493)

  *

  Gregor Wagner, Olli Pettay, Gary Kwong, Jesse
  Ruderman, Luke Wagner, Rob Fletcher, and Makoto Kato
  reported memory safety problems and crashes that affect
  Firefox 27. (CVE-2014-1494)

  *

  MFSA 2014-16 / CVE-2014-1496: Security researcher Ash
  reported an issue where the extracted files for updates to
  existing files are not read only during the update process.
  This allows for the potential replacement or modification
  of these files during the update process if a malicious
  application is present on the local system.

  *

  MFSA 2014-17 / CVE-2014-1497: Security researcher
  Atte Kettunen from OUSPG reported an out of bounds read
  during the decoding of WAV format audio files for playback.
  This could allow web content access to heap data as well as
  causing a crash.

  *

  MFSA 2014-18 / CVE-2014-1498: Mozilla developer David
  Keeler reported that the crypto.generateCRFMRequest method
  did not correctly validate the key type of the KeyParams
  argument when generating ec-dual-use requests. This could
  lead to a crash and a denial of service (DOS) attack.

  *

  MFSA 2014-19 / CVE-2014-1499: Mozilla developer Ehsan
  Akhgari reported a spoofing attack where the permission
  prompt for a WebRTC session can appear to be from a
  different site than its actual originating site if a timed
  navigation occurs during the prompt generation. This allows
  an attacker to potentially gain access to the webcam or
  microphone by masquerading as another site and gaining user
  permission through spoofing.

  *

  MFSA 2014-20 / CVE-2014-1500: Security researchers
  Tim Philipp Schaefers and Sebastian Neef, the team of
  Internetwache.org, reported a mechanism using JavaScript
  onbeforeunload events with page navigation to prevent users
  from closing a malicious page's tab and causing the browser
  to become unresponsive. This allows for a denial of service ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"MozillaFirefox on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES11.0SP3")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~24.4.0esr~0.8.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED-24", rpm:"MozillaFirefox-branding-SLED-24~0.7.23", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~24.4.0esr~0.8.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.10.4~0.3.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.10.4~0.3.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-x86", rpm:"mozilla-nspr-x86~4.10.4~0.3.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
