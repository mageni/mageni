###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for wpa_supplicant CESA-2015:1090 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882197");
  script_version("$Revision: 14058 $");
  script_cve_id("CVE-2015-1863", "CVE-2015-4142");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-06-16 06:13:00 +0200 (Tue, 16 Jun 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for wpa_supplicant CESA-2015:1090 centos7");
  script_tag(name:"summary", value:"Check the version of wpa_supplicant");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The wpa_supplicant package contains an 802.1X
  Supplicant with support for
WEP, WPA, WPA2 (IEEE 802.11i / RSN), and various EAP authentication
methods. It implements key negotiation with a WPA Authenticator for client
stations and controls the roaming and IEEE 802.11 authentication and
association of the WLAN driver.

A buffer overflow flaw was found in the way wpa_supplicant handled SSID
information in the Wi-Fi Direct / P2P management frames. A specially
crafted frame could allow an attacker within Wi-Fi radio range to cause
wpa_supplicant to crash or, possibly, execute arbitrary code.
(CVE-2015-1863)

An integer underflow flaw, leading to a buffer over-read, was found in the
way wpa_supplicant handled WMM Action frames. A specially crafted frame
could possibly allow an attacker within Wi-Fi radio range to cause
wpa_supplicant to crash. (CVE-2015-4142)

Red Hat would like to thank Jouni Malinen of the wpa_supplicant upstream
for reporting the CVE-2015-1863 issue. Upstream acknowledges Alibaba
security team as the original reporter.

This update also adds the following enhancement:

  * Prior to this update, wpa_supplicant did not provide a way to require the
host name to be listed in an X.509 certificate's Common Name or Subject
Alternative Name, and only allowed host name suffix or subject substring
checks. This update introduces a new configuration directive,
'domain_match', which adds a full host name check. (BZ#1178263)

All wpa_supplicant users are advised to upgrade to this updated package,
which contains backported patches to correct these issues and add this
enhancement. After installing this update, the wpa_supplicant service will
be restarted automatically.");
  script_tag(name:"affected", value:"wpa_supplicant on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-June/021171.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.0~17.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
