###############################################################################
# OpenVAS Vulnerability Test
# $Id: mgasa-2015-0413.nasl 11692 2018-09-28 16:55:19Z cfischer $
#
# Mageia Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131100");
  script_version("$Revision: 11692 $");
  script_tag(name:"creation_date", value:"2015-10-26 09:35:58 +0200 (Mon, 26 Oct 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 18:55:19 +0200 (Fri, 28 Sep 2018) $");
  script_name("Mageia Linux Local Check: mgasa-2015-0413");
  script_tag(name:"insight", value:"It was found that ntpd did not correctly implement the threshold limitation for the '-g' option, which is used to set the time without any restrictions. A man-in-the-middle attacker able to intercept NTP traffic between a connecting client and an NTP server could use this flaw to force that client to make multiple steps larger than the panic threshold, effectively changing the time to an arbitrary value at any time (CVE-2015-5300). Slow memory leak in CRYPTO_ASSOC with autokey (CVE-2015-7701). Incomplete autokey data packet length checks could result in crash caused by a crafted packet (CVE-2015-7691, CVE-2015-7692, CVE-2015-7702). Clients that receive a KoD should validate the origin timestamp field (CVE-2015-7704). ntpq atoascii() Memory Corruption Vulnerability could result in ntpd crash caused by a crafted packet (CVE-2015-7852). Symmetric association authentication bypass via crypto-NAK (CVE-2015-7871).");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0413.html");
  script_cve_id("CVE-2015-5300", "CVE-2015-7701", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7702", "CVE-2015-7704", "CVE-2015-7852", "CVE-2015-7871");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Mageia Linux Local Security Checks mgasa-2015-0413");
  script_copyright("Eero Volotinen");
  script_family("Mageia Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~24.2.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
