###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for ntp RHSA-2016:0780-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871612");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-11 05:23:05 +0200 (Wed, 11 May 2016)");
  script_cve_id("CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5219", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7852", "CVE-2015-7977", "CVE-2015-7978", "CVE-2014-9750");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for ntp RHSA-2016:0780-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Network Time Protocol (NTP) is used to synchronize a computer's time
with another referenced time source. These packages include the ntpd
service which continuously adjusts system time and utilities used to query
and configure the ntpd service.

Security Fix(es):

  * It was found that the fix for CVE-2014-9750 was incomplete: three issues
were found in the value length checks in NTP's ntp_crypto.c, where a packet
with particular autokey operations that contained malicious data was not
always being completely validated. A remote attacker could use a specially
crafted NTP packet to crash ntpd. (CVE-2015-7691, CVE-2015-7692,
CVE-2015-7702)

  * A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If ntpd was
configured to use autokey authentication, an attacker could send packets to
ntpd that would, after several days of ongoing attack, cause it to run out
of memory. (CVE-2015-7701)

  * An off-by-one flaw, leading to a buffer overflow, was found in
cookedprint functionality of ntpq. A specially crafted NTP packet could
potentially cause ntpq to crash. (CVE-2015-7852)

  * A NULL pointer dereference flaw was found in the way ntpd processed
'ntpdc reslist' commands that queried restriction lists with a large amount
of entries. A remote attacker could potentially use this flaw to crash
ntpd. (CVE-2015-7977)

  * A stack-based buffer overflow flaw was found in the way ntpd processed
'ntpdc reslist' commands that queried restriction lists with a large amount
of entries. A remote attacker could use this flaw to crash ntpd.
(CVE-2015-7978)

  * It was found that ntpd could crash due to an uninitialized variable when
processing malformed logconfig configuration commands. (CVE-2015-5194)

  * It was found that ntpd would exit with a segmentation fault when a
statistics type that was not enabled during compilation (e.g. timingstats)
was referenced by the statistics or filegen configuration command.
(CVE-2015-5195)

  * It was discovered that the sntp utility could become unresponsive due to
being caught in an infinite loop when processing a crafted NTP packet.
(CVE-2015-5219)

  * It was found that NTP's :config command could be used to set the pidfile
and driftfile paths without any restrictions. A remote attacker could use
this flaw to overwrite a file on the file system with a file containing the
pid of the ntpd process (immediately) or the current estimated drift of the
system clock (in hourly intervals). (CVE-2015-7703)

The CVE-2015-5219 and CVE-2015-7703 issues were discovered by Miroslav
Lichvar (R ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"ntp on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-May/msg00022.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~10.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~10.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~10.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
