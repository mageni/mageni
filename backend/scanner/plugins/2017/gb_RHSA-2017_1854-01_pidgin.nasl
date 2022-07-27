###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_1854-01_pidgin.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for pidgin RHSA-2017:1854-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871854");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:47:19 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3698",
                "CVE-2017-2640");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for pidgin RHSA-2017:1854-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'pidgin'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Pidgin is an instant messaging program which
  can log in to multiple accounts on multiple instant messaging networks
  simultaneously. The following packages have been upgraded to a later upstream
  version: pidgin (2.10.11). (BZ#1369526) Security Fix(es): * A denial of service
  flaw was found in the way Pidgin's Mxit plug-in handled emoticons. A malicious
  remote server or a man-in-the-middle attacker could potentially use this flaw to
  crash Pidgin by sending a specially crafted emoticon. (CVE-2014-3695) * A denial
  of service flaw was found in the way Pidgin parsed Groupwise server messages. A
  malicious remote server or a man-in-the-middle attacker could potentially use
  this flaw to cause Pidgin to consume an excessive amount of memory, possibly
  leading to a crash, by sending a specially crafted message. (CVE-2014-3696) * An
  information disclosure flaw was discovered in the way Pidgin parsed XMPP
  messages. A malicious remote server or a man-in-the-middle attacker could
  potentially use this flaw to disclose a portion of memory belonging to the
  Pidgin process by sending a specially crafted XMPP message. (CVE-2014-3698) * An
  out-of-bounds write flaw was found in the way Pidgin processed XML content. A
  malicious remote server could potentially use this flaw to crash Pidgin or
  execute arbitrary code in the context of the pidgin process. (CVE-2017-2640) *
  It was found that Pidgin's SSL/TLS plug-ins had a flaw in the certificate
  validation functionality. An attacker could use this flaw to create a fake
  certificate, that Pidgin would trust, which could be used to conduct
  man-in-the-middle attacks against Pidgin. (CVE-2014-3694) Red Hat would like to
  thank the Pidgin project for reporting these issues. Upstream acknowledges Yves
  Younan (Cisco Talos) and Richard Johnson (Cisco Talos) as the original reporters
  of CVE-2014-3695 and CVE-2014-3696 Thijs Alkemade and Paul Aurich as the
  original reporters of CVE-2014-3698 and Jacob Appelbaum and Moxie Marlinspike as
  the original reporters of CVE-2014-3694. Additional Changes: For detailed
  information on changes in this release, see the Red Hat Enterprise Linux 7.4
  Release Notes linked from the References section.");
  script_tag(name:"affected", value:"pidgin on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00019.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.10.11~5.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-debuginfo", rpm:"pidgin-debuginfo~2.10.11~5.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}