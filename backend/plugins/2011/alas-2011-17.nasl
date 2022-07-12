###############################################################################
# OpenVAS Vulnerability Test
# $Id: alas-2011-17.nasl 11703 2018-10-01 08:05:31Z cfischer $
#
# Amazon Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@iki.fi>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org
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
  script_oid("1.3.6.1.4.1.25623.1.0.120294");
  script_version("$Revision: 11703 $");
  script_tag(name:"creation_date", value:"2015-09-08 11:22:15 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 10:05:31 +0200 (Mon, 01 Oct 2018) $");
  script_name("Amazon Linux Local Check: ALAS-2011-17");
  script_tag(name:"insight", value:"The Net::HTTPS module in libwww-perl (LWP) before 6.00, as used in WWW::Mechanize, LWP::UserAgent, and other products, when running in environments that do not set the If-SSL-Cert-Subject header, does not enable full validation of SSL certificates by default, which allows remote attackers to spoof servers via man-in-the-middle (MITM) attacks involving hostnames that are not properly validated. NOTE: it could be argued that this is a design limitation of the Net::HTTPS API, and separate implementations should be independently assigned CVE identifiers for not working around this limitation. However, because this API was modified within LWP, a single CVE identifier has been assigned.");
  script_tag(name:"solution", value:"Run yum update perl-libwww-perl to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2011-17.html");
  script_cve_id("CVE-2011-0633");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
  script_copyright("Eero Volotinen");
  script_family("Amazon Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"perl-libwww-perl", rpm:"perl-libwww-perl~5.837~4.1.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
