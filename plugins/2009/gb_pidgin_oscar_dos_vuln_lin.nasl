###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_oscar_dos_vuln_lin.nasl 12670 2018-12-05 14:14:20Z cfischer $
#
# Pidgin OSCAR Protocol Denial Of Service Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:pidgin:pidgin';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800824");
  script_version("$Revision: 12670 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 15:14:20 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1889");
  script_bugtraq_id(35530);
  script_name("Pidgin OSCAR Protocol Denial Of Service Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_lin.nasl");
  script_mandatory_keys("Pidgin/Lin/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35652");
  script_xref(name:"URL", value:"http://developer.pidgin.im/ticket/9483");
  script_xref(name:"URL", value:"http://pidgin.im/pipermail/devel/2009-May/008227.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a application crash.");

  script_tag(name:"affected", value:"Pidgin version prior to 2.5.8 on Linux");

  script_tag(name:"insight", value:"Error in OSCAR protocol implementation leads to the application misinterpreting
  the ICQWebMessage message type as ICQSMS message type via a crafted ICQ web
  message that triggers allocation of a large amount of memory.");

  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.5.8.");

  script_tag(name:"summary", value:"This host has installed Pidgin and is prone to Denial of Service
  vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE)) exit(0);

if(version_is_less(version:ver, test_version:"2.5.8")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.5.8");
  security_message(data:report);
  exit(0);
}

exit(99);