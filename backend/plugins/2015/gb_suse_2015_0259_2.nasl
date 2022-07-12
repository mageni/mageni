###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0259_2.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for ntp SUSE-SU-2015:0259-2 (ntp)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851113");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 20:17:02 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2014-9293", "CVE-2014-9294", "CVE-2014-9297", "CVE-2014-9298");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for ntp SUSE-SU-2015:0259-2 (ntp)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"ntp has been updated to fix four security issues:

  * CVE-2014-9294: ntp-keygen used a weak RNG seed, which made it easier
  for remote attackers to defeat cryptographic protection mechanisms
  via a brute-force attack. (bsc#910764)

  * CVE-2014-9293: The config_auth function, when an auth key is not
  configured, improperly generated a key, which made it easier for
  remote attackers to defeat cryptographic protection mechanisms via a
  brute-force attack. (bsc#910764)

  * CVE-2014-9298: ::1 can be spoofed on some operating systems, so ACLs
  based on IPv6 ::1 addresses could be bypassed. (bsc#910764)

  * CVE-2014-9297: vallen is not validated in several places in
  ntp_crypto.c, leading to potential information leak. (bsc#910764)

  Security Issues:

  * CVE-2014-9294

  * CVE-2014-9293

  * CVE-2014-9298

  * CVE-2014-9297");
  script_tag(name:"affected", value:"ntp on SUSE Linux Enterprise Server 11 SP2 LTSS");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES11.0SP2")
{

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.4p8~1.29.32.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.4p8~1.29.32.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
