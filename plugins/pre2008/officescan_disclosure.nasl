# OpenVAS Vulnerability Test
# $Id: officescan_disclosure.nasl 14193 2019-03-14 15:07:17Z cfischer $
# Description: OfficeScan configuration file disclosure
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

# References:
# Date:  Tue, 16 Oct 2001 11:34:56 +0900
# From: "snsadv@lac.co.jp" <snsadv@lac.co.jp>
# To: bugtraq@securityfocus.com
# Subject: [SNS Advisory No.44] Trend Micro OfficeScan Corporate Edition
# (Virus Buster Corporate Edition) Configuration File Disclosure Vulnerability

CPE = "cpe:/a:trendmicro:officescan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11074");
  script_version("$Revision: 14193 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 16:07:17 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-1151");
  script_bugtraq_id(3438);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("OfficeScan configuration file disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("gb_trend_micro_office_scan_detect_remote.nasl");
  script_mandatory_keys("TrendMicro/OfficeScan/Installed/Remote");

  script_tag(name:"solution", value:"Upgrade OfficeScan.");

  script_tag(name:"summary", value:"Trend Micro OfficeScan Corporate Edition (Japanese version: Virus
  Buster Corporate Edition) web-based management console let anybody
  access /officescan/hotdownload without authentication.");

  script_tag(name:"impact", value:"Reading the configuration file /officescan/hotdownload/ofcscan.ini
  will reveal information on your system. More, it contains passwords that are encrypted by a weak
  specific algorithm, so they might be decrypted.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE))
  exit(0);

url = "/officescan/hotdownload/ofscan.ini";
res = is_cgi_installed_ka(port:port, item:url);
if(!res)
  exit(99);

res = is_cgi_installed_ka(port:port, item:"/officescan/hotdownload/vt-test.ini");
if(res)
  exit(0);

report = report_vuln_url(port:port, url:url);
security_message(port:port, data:report);

exit(0);