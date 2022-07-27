###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_netweaver_info_disc_vuln.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# SAP NetWeaver WD_CHAT Information Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:sap:netweaver';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106149");
  script_version("$Revision: 14181 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-07-22 14:30:27 +0700 (Fri, 22 Jul 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-3973");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SAP NetWeaver WD_CHAT Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sap_netweaver_detect.nasl");
  script_mandatory_keys("sap_netweaver/installed");

  script_tag(name:"summary", value:"SAP NetWeaver is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if WD_CHAT is accessible.");

  script_tag(name:"insight", value:"The chat feature in the Real-Time Collaboration (RTC) services allows
  remote attackers to obtain sensitive user information.");

  script_tag(name:"impact", value:"An unauthenticated  attacker can get information about SAP NetWeaver
  users.");

  script_tag(name:"affected", value:"Version 7.1 - 7.5");

  script_tag(name:"solution", value:"Check the references for solutions.");

  script_xref(name:"URL", value:"https://erpscan.com/advisories/erpscan-16-016-sap-netweaver-7-4-information-disclosure-wd_chat/");
  script_xref(name:"URL", value:"https://service.sap.com/sap/support/notes/2255990");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (version = get_app_version(cpe: CPE, port: port)) {
  if (version !~ "^7.[1-5]")
    exit(0);
}

url = "/webdynpro/resources/sap.com/tc~rtc~coll.appl.rtc~wd_chat/Chat";

if (http_vuln_check(port: port, url: url, pattern: "set-cookie", check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);