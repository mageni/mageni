###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for wpa_supplicant RHSA-2015:1439-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871403");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2015-4142");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-07-23 06:25:40 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for wpa_supplicant RHSA-2015:1439-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa_supplicant'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The wpa_supplicant package contains an 802.1X Supplicant with support for
WEP, WPA, WPA2 (IEEE 802.11i / RSN), and various EAP authentication
methods. It implements key negotiation with a WPA Authenticator for client
stations and controls the roaming and IEEE 802.11 authentication and
association of the WLAN driver.

An integer underflow flaw, leading to a buffer over-read, was found in the
way wpa_supplicant handled WMM Action frames. A specially crafted frame
could possibly allow an attacker within Wi-Fi radio range to cause
wpa_supplicant to crash. (CVE-2015-4142)

This update includes the following enhancement:

  * Prior to this update, wpa_supplicant did not provide a way to require the
host name to be listed in an X.509 certificate's Common Name or Subject
Alternative Name, and only allowed host name suffix or subject substring
checks. This update introduces a new configuration directive,
'domain_match', which adds a full host name check. (BZ#1186806)

All wpa_supplicant users are advised to upgrade to this updated package,
which contains a backported patch to correct this issue and adds this
enhancement. After installing this update, the wpa_supplicant service will
be restarted automatically.");
  script_tag(name:"affected", value:"wpa_supplicant on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00032.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~0.7.3~6.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant-debuginfo", rpm:"wpa_supplicant-debuginfo~0.7.3~6.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
