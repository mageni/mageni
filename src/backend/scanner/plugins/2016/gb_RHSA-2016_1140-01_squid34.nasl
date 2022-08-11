###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for squid34 RHSA-2016:1140-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871626");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-03 16:25:15 +0530 (Fri, 03 Jun 2016)");
  script_cve_id("CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054",
                "CVE-2016-4553", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556",
                "CVE-2009-0801");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for squid34 RHSA-2016:1140-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid34'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The 'squid34' packages provide version 3.4
of Squid, a high-performance proxy caching server for web clients, supporting FTP,
Gopher, and HTTP data objects. Note that apart from 'squid34', this version of Red
Hat Enterprise Linux also includes the 'squid' packages which provide Squid version 3.1.

Security Fix(es):

  * A buffer overflow flaw was found in the way the Squid cachemgr.cgi
utility processed remotely relayed Squid input. When the CGI interface
utility is used, a remote attacker could possibly use this flaw to execute
arbitrary code. (CVE-2016-4051)

  * Buffer overflow and input validation flaws were found in the way Squid
processed ESI responses. If Squid was used as a reverse proxy, or for
TLS/HTTPS interception, a remote attacker able to control ESI components on
an HTTP server could use these flaws to crash Squid, disclose parts of the
stack memory, or possibly execute arbitrary code as the user running Squid.
(CVE-2016-4052, CVE-2016-4053, CVE-2016-4054)

  * An input validation flaw was found in the way Squid handled intercepted
HTTP Request messages. An attacker could use this flaw to bypass the
protection against issues related to CVE-2009-0801, and perform cache
poisoning attacks on Squid. (CVE-2016-4553)

  * An input validation flaw was found in Squid's mime_get_header_field()
function, which is used to search for headers within HTTP requests. An
attacker could send an HTTP request from the client side with specially
crafted header Host header that bypasses same-origin security protections,
causing Squid operating as interception or reverse-proxy to contact the
wrong origin server. It could also be used for cache poisoning for client
not following RFC 7230. (CVE-2016-4554)

  * A NULL pointer dereference flaw was found in the way Squid processes ESI
responses. If Squid was used as a reverse proxy or for TLS/HTTPS
interception, a malicious server could use this flaw to crash the Squid
worker process. (CVE-2016-4555)

  * An incorrect reference counting flaw was found in the way Squid processes
ESI responses. If Squid is configured as reverse-proxy, for TLS/HTTPS
interception, an attacker controlling a server accessed by Squid, could
crash the squid worker, causing a Denial of Service attack. (CVE-2016-4556)");
  script_tag(name:"affected", value:"squid34 on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-May/msg00054.html");
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

  if ((res = isrpmvuln(pkg:"squid34", rpm:"squid34~3.4.14~9.el6_8.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squid34-debuginfo", rpm:"squid34-debuginfo~3.4.14~9.el6_8.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
