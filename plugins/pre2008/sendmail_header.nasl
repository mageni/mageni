# OpenVAS Vulnerability Test
# $Id: sendmail_header.nasl 13074 2019-01-15 09:12:34Z cfischer $
# Description: Sendmail remote header buffer overflow
#
# Authors:
# Michael Scheidell SECNAP Network Security
#
# Copyright:
# Copyright (C) 2003 SECNAP Network Security
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:sendmail:sendmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11316");
  script_version("$Revision: 13074 $");
  script_bugtraq_id(2794, 6991);
  script_cve_id("CVE-2001-1349", "CVE-2002-1337");
  script_tag(name:"last_modification", value:"$Date: 2019-01-15 10:12:34 +0100 (Tue, 15 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Sendmail remote header buffer overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 SECNAP Network Security");
  script_family("SMTP problems");
  script_dependencies("gb_sendmail_detect.nasl");
  script_mandatory_keys("sendmail/detected");

  script_xref(name:"URL", value:"http://www.sendmail.org/patchcr.html");
  script_xref(name:"URL", value:"http://www.iss.net/issEn/delivery/xforce/alertdetail.jsp?oid=21950");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2003-07.html");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/398025");

  script_tag(name:"solution", value:"Upgrade to Sendmail version 8.12.8 or later.
  If you cannot upgrade, apply patches for 8.10-12 from the linked references.");

  script_tag(name:"summary", value:"The remote sendmail server, according to its version number,
  may be vulnerable to a remote buffer overflow allowing remote users to gain root privileges.");

  script_tag(name:"affected", value:"Sendmail versions from 5.79 to 8.12.7 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"5.79", test_version2:"8.12.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.12.8");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);