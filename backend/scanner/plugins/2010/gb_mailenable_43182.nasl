###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mailenable_43182.nasl 13467 2019-02-05 12:16:48Z cfischer $
#
# MailEnable  'MESMTRPC.exe' SMTP Service Multiple Remote Denial of Service Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100798");
  script_version("$Revision: 13467 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 13:16:48 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-09-14 15:16:41 +0200 (Tue, 14 Sep 2010)");
  script_bugtraq_id(43182);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-2580");
  script_name("MailEnable  'MESMTRPC.exe' SMTP Service Multiple Remote Denial of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("SMTP problems");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("smtpserver_detect.nasl");
  script_mandatory_keys("smtp/mailenable/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43182");
  script_xref(name:"URL", value:"http://www.mailenable.com/");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-112/");
  script_xref(name:"URL", value:"http://www.mailenable.com/hotfix/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/513648");

  script_tag(name:"solution", value:"The vendor has released hotfix ME-10044. Please see the references for
  more information.");

  script_tag(name:"summary", value:"According to its banner, the remote MailEnable is prone to multiple
  remote denial-of-service vulnerabilities.");

  script_tag(name:"impact", value:"An attacker can exploit these issue to crash the affected application,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"MailEnable 4.25 Standard Edition, Professional Edition, and Enterprise
  Edition are vulnerable. Other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("smtp_func.inc");

port = get_smtp_port(default:25);

banner = get_smtp_banner(port:port);
if(!banner || !egrep( pattern:"Mail(Enable| Enable SMTP) Service", string:banner))
  exit(0);

version = eregmatch(pattern:"Version: ([0-9.]+)", string:banner);
if(!version[1])
  exit(0);

if(version_is_less(version:version[1], test_version:"4.26")) {
  report = report_fixed_ver(installed_version:version[1], fixed_version:"4.26");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);