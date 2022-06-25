###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for ntp RHSA-2015:1459-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871405");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2014-9750", "CVE-2014-9751", "CVE-2015-1799", "CVE-2015-3405");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-07-23 06:26:09 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for ntp RHSA-2015:1459-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Network Time Protocol (NTP) is used to synchronize a computer's time
with another referenced time source.

It was found that because NTP's access control was based on a source IP
address, an attacker could bypass source IP restrictions and send malicious
control and configuration packets by spoofing ::1 addresses.
(CVE-2014-9298)

A denial of service flaw was found in the way NTP hosts that were peering
with each other authenticated themselves before updating their internal
state variables. An attacker could send packets to one peer host, which
could cascade to other peers, and stop the synchronization process among
the reached peers. (CVE-2015-1799)

A flaw was found in the way the ntp-keygen utility generated MD5 symmetric
keys on big-endian systems. An attacker could possibly use this flaw to
guess generated MD5 keys, which could then be used to spoof an NTP client
or server. (CVE-2015-3405)

A stack-based buffer overflow was found in the way the NTP autokey protocol
was implemented. When an NTP client decrypted a secret received from an NTP
server, it could cause that client to crash. (CVE-2014-9750)

It was found that ntpd did not check whether a Message Authentication Code
(MAC) was present in a received packet when ntpd was configured to use
symmetric cryptographic keys. A man-in-the-middle attacker could use this
flaw to send crafted packets that would be accepted by a client or a peer
without the attacker knowing the symmetric key. (CVE-2014-9751)

The CVE-2015-1798 and CVE-2015-1799 issues were discovered by Miroslav
Lichvar of Red Hat.

Bug fixes:

  * The ntpd daemon truncated symmetric keys specified in the key file to 20
bytes. As a consequence, it was impossible to configure NTP authentication
to work with peers that use longer keys. The maximum length of keys has now
been changed to 32 bytes. (BZ#1053551)

  * The ntp-keygen utility used the exponent of 3 when generating RSA keys,
and generating RSA keys failed when FIPS mode was enabled. ntp-keygen has
been modified to use the exponent of 65537, and generating keys in FIPS
mode now works as expected. (BZ#1184421)

  * The ntpd daemon included a root delay when calculating its root
dispersion. Consequently, the NTP server reported larger root dispersion
than it should have and clients could reject the source when its distance
reached the maximum synchronization distance (1.5 seconds by default).
Calculation of root dispersion has been fixed, the root dispersion is now
reported correctly, and clients no longer reject t ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"ntp on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00036.html");
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

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
