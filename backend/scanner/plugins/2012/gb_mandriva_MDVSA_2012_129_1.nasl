###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for busybox MDVSA-2012:129-1 (busybox)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:129-1");
  script_oid("1.3.6.1.4.1.25623.1.0.831720");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-08-14 10:42:00 +0530 (Tue, 14 Aug 2012)");
  script_cve_id("CVE-2006-1168", "CVE-2011-2716");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandriva Update for busybox MDVSA-2012:129-1 (busybox)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2011\.0");
  script_tag(name:"affected", value:"busybox on Mandriva Linux 2011.0");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple vulnerabilities was found and corrected in busybox:

  The decompress function in ncompress allows remote attackers to cause
  a denial of service (crash), and possibly execute arbitrary code,
  via crafted data that leads to a buffer underflow (CVE-2006-1168).

  A missing DHCP option checking / sanitization flaw was reported for
  multiple DHCP clients.  This flaw may allow DHCP server to trick DHCP
  clients to set e.g. system hostname to a specially crafted value
  containing shell special characters.  Various scripts assume that
  hostname is trusted, which may lead to code execution when hostname
  is specially crafted (CVE-2011-2716).

  Additionally for Mandriva Enterprise Server 5 various problems in
  the ka-deploy and uClibc packages was discovered and fixed with
  this advisory.

  The updated packages have been patched to correct these issues.

  Update:
  The wrong set of packages was sent out with the MDVSA-2012:129 advisory
  that lacked the fix for CVE-2006-1168. This advisory provides the
  correct packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.18.4~3.2", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.18.4~3.2", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
